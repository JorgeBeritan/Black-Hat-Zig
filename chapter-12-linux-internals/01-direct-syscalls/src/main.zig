const std = @import("std");
const linux = std.os.linux;
const SYS = linux.SYS;

const O_RDONLY: u64 = 0;
const AT_FDCWD: u64 = @bitCast(@as(i64, -100));

const MemRegion = struct {
    start: u64,
    end: u64,
    perms: [4]u8,
    path: []const u8,
};

const Utsname = extern struct {
    sysname: [65]u8,
    nodename: [65]u8,
    release: [65]u8,
    version: [65]u8,
    machine: [65]u8,
    domainname: [65]u8,
};

fn checkSyscallResult(ret: u64) !u64 {
    const signed: i64 = @bitCast(ret);
    if (signed < 0) {
        std.debug.print("[!] Syscall failed with errno: {d}.\n", .{-signed});
        return error.SyscallFailed;
    }
    return ret;
}

fn rawWrite(fd: u64, buf: []const u8) !void {
    _ = try checkSyscallResult(
        linux.syscall3(.write, fd, @intFromPtr(buf.ptr), buf.len),
    );
}

fn rawUname() !Utsname {
    var info: Utsname = undefined;
    _ = try checkSyscallResult(
        linux.syscall1(.uname, @intFromPtr(&info)),
    );
    return info;
}

fn printField(label: []const u8, field: []const u8) void {
    const end = std.mem.indexOfScalar(u8, field, 0) orelse field.len;
    std.debug.print("{s}: {s}\n", .{ label, field[0..end] });
}

fn rawRead(fd: u64, buf: []u8) !u64 {
    return try checkSyscallResult(linux.syscall3(.read, fd, @intFromPtr(buf.ptr), buf.len));
}

fn rawOpenat(path: [*:0]const u8) !u64 {
    return try checkSyscallResult(linux.syscall4(.openat, AT_FDCWD, @intFromPtr(path), O_RDONLY, 0));
}

fn rawClose(fd: u64) void {
    _ = linux.syscall1(.close, fd);
}

fn rawGetpid() !u64 {
    return try checkSyscallResult(linux.syscall0(.getpid));
}

fn rawGetuid() !u64 {
    return try checkSyscallResult(linux.syscall0(.getuid));
}

fn rawGetppid() !u64 {
    return try checkSyscallResult(linux.syscall0(.getppid));
}

fn parseHexAddr(buf: []const u8) u64 {
    var result: u64 = 0;
    for (buf) |c| {
        const digit: u64 = switch (c) {
            '0'...'9' => c - '0',
            'a'...'f' => c - 'a' + 10,
            else => break,
        };
        result = (result << 4) | digit;
    }
    return result;
}

fn parseMapsLine(line: []const u8) ?MemRegion {
    // Format: start-end perms offset dev inode [path]
    const dash = std.mem.indexOfScalar(u8, line, '-') orelse return null;
    const start = parseHexAddr(line[0..dash]);

    const space1 = std.mem.indexOfScalarPos(u8, line, dash, ' ') orelse return null;
    const end = parseHexAddr(line[dash + 1 .. space1]);

    if (space1 + 5 > line.len) return null;
    const perms = line[space1 + 1 ..][0..4].*;

    var col_count: u32 = 0;
    var i: usize = space1 + 1;
    while (i < line.len and col_count < 4) : (i += 1) {
        if (line[i] == ' ' and (i + 1 >= line.len or line[i + 1] != ' ')) {
            col_count += 1;
        }
    }

    while (i < line.len and line[i] == ' ') : (i += 1) {}

    const path = if (i < line.len) line[i..] else "";

    return MemRegion{
        .start = start,
        .end = end,
        .perms = perms,
        .path = path,
    };
}

fn readProcMaps() !void {
    const fd = try rawOpenat("/proc/self/maps");
    defer rawClose(fd);

    var buf: [8192]u8 = undefined;
    var total_read: usize = 0;

    while (true) {
        const n = try rawRead(fd, buf[total_read..]);
        if (n == 0) break;
        total_read += n;
        if (total_read >= buf.len) break;
    }

    const content = buf[0..total_read];

    std.debug.print("[*] Memory map ({d} bytes read):\n\n", .{total_read});
    std.debug.print("{s:<20} {s:<6} {s:<10} {s}\n", .{ "ADDRESS RANGE", "PERMS", "SIZE", "PATH" });
    std.debug.print("{s:-<70}\n", .{""});

    var rwx_count: u32 = 0;
    var exec_count: u32 = 0;

    var line_start: usize = 0;
    for (content, 0..) |c, idx| {
        if (c == '\n') {
            const line = content[line_start..idx];
            if (parseMapsLine(line)) |region| {
                if (region.end < region.start) continue;
                const size = region.end - region.start;
                const size_kb = size / 1024;

                const marker: []const u8 = if (region.perms[2] == 'x') " <-- EXEC" else "";

                std.debug.print("{x:>12}-{x:0>12} {s} {d:6}KB {s}{s}\n", .{ region.start, region.end, &region.perms, size_kb, region.path, marker });
                if (region.perms[2] == 'x') exec_count += 1;
                if (region.perms[0] == 'r' and region.perms[1] == 'w' and region.perms[2] == 'x') rwx_count += 1;
            }
            line_start += 1;
        }
    }

    std.debug.print("\n[*] Summary:\n", .{});
    std.debug.print("Executable regions: {d}\n", .{exec_count});
    std.debug.print("RWX regions:        {d}", .{rwx_count});
    if (rwx_count > 0) {
        std.debug.print("(!) writable + executable = potential injection target", .{});
    }
    std.debug.print("\n", .{});
}

pub fn main(init: std.process.Init) !void {
    _ = init;

    try rawWrite(1, "\n[*] Black Hat Zig - Directo Syscalls Demo\n");
    try rawWrite(1, "\n[*] All output below bypasses libc\n\n");

    const pid = try rawGetpid();
    const uid = try rawGetuid();
    const ppid = try rawGetppid();

    std.debug.print("PID: {d}\nUID: {d}\nPPID: {d}\n", .{ pid, uid, ppid });

    const info = try rawUname();

    std.debug.print("\n[*] System Info:\n", .{});
    printField("Kernel: ", &info.sysname);
    printField("Host: ", &info.nodename);
    printField("Release: ", &info.release);
    printField("Version: ", &info.version);
    printField("Arch: ", &info.machine);

    try rawWrite(1, "\n[*] Reading /proc/self/maps via raw openat+read syscalls...\n\n");
    try readProcMaps();

    try rawWrite(1, "[*] Done. Zero libc calls were made.\n");
}
