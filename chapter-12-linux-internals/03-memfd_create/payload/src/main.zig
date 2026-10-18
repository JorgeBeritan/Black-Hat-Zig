const std = @import("std");
const linux = std.os.linux;

fn rawWrite(fd: u64, buf: []const u8) void {
    _ = linux.syscall3(.write, fd, @intFromPtr(buf.ptr), buf.len);
}

pub fn main(_: std.process.Init) !void {
    rawWrite(1,
        \\
        \\  ============================================
        \\  [!] PAYLOAD EJECUTADO DESDE MEMORIA
        \\  [!] Este binario NO existe en disco
        \\  [!] memfd_create + execveat = fileless exec
        \\  ============================================
        \\
        \\
    );
}
