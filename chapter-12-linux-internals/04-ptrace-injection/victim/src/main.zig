const std = @import("std");
const linux = std.os.linux;

fn rawGetpid() u64 {
    return linux.syscall0(.getpid);
}

fn rawNanosleep(seconds: u64) void {
    const ts = linux.timespec{ .sec = @intCast(seconds), .nsec = 0 };
    _ = linux.syscall2(.nanosleep, @intFromPtr(&ts), 0);
}

pub fn main(_: std.process.Init) !void {
    const pid = rawGetpid();
    std.debug.print("[victim] PID: {d}\n", .{pid});
    std.debug.print("[victim] Running... \n", .{});

    var count: u64 = 0;
    while (true) {
        count += 1;
        std.debug.print("[victim] heartbeat: {d}\n", .{count});
        rawNanosleep(2);
    }
}
