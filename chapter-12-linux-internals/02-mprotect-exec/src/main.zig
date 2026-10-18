const std = @import("std");
const linux = std.os.linux;

fn checkSyscallResult(ret: u64) !u64 {
    const signed: u64 = @bitCast(ret);
    if (signed < 0) {
        std.debug.print("[!] Syscall failed with errno: {d}\n", .{-signed});
        return error.SyscallFailed;
    }
    return ret;
}

fn rawWrite(fd: u64, buf: []const u8) !void {
    _ = try checkSyscallResult(linux.syscall3(.write, fd, @intFromPtr(buf.ptr), buf.len));
}

const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const PROT_EXEC: u64 = 0x4;

const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;

fn rawMmap(size: u64, prot: u64, flags: u64) !u64 {
    return try checkSyscallResult(linux.syscall6(.mmap, 0, size, prot, flags, @bitCast(@as(i64, -1)), 0));
}

fn rawMprotect(addr: u64, size: u64, prot: u64) !void {
    _ = try checkSyscallResult(linux.syscall3(.mprotect, addr, size, prot));
}

fn rawMunmap(addr: u64, size: u64) void {
    _ = try checkSyscallResult(linux.syscall2(.munmap, addr, size));
}

pub fn main(_: std.process.Init) !void {
    try rawWrite(1, "[*] Black Hat Zig - mprotect Shellcode Execution\n");
    try rawWrite(1, "[*] ================================================\n\n");

    const shellcode = [_]u8{
        // mov eax, 1 (syscall: write)
        0xb8, 0x01, 0x00, 0x00, 0x00,
        // mov edi, 1 (fd: stdout)
        0xbf, 0x01, 0x00, 0x00, 0x00,
        // lea rsi, [rip+8] (puntero al mensaje)
        0x48, 0x8d, 0x35, 0x08, 0x00,
        0x00, 0x00,
        // mov edx, 43 (longitud)
        0xba, 0x2b, 0x00,
        0x00, 0x00,
        // syscall
        0x0f, 0x05,
        // ret
        0xc3,
        // "[!] mprotect + shellcode = code execution!\n"
        0x5b, 0x21, 0x5d, 0x20, 0x6d,
        0x70, 0x72, 0x6f, 0x74, 0x65,
        0x63, 0x74, 0x20, 0x2b, 0x20,
        0x73, 0x68, 0x65, 0x6c, 0x6c,
        0x63, 0x6f, 0x64, 0x65, 0x20,
        0x3d, 0x20, 0x63, 0x6f, 0x64,
        0x65, 0x20, 0x65, 0x78, 0x65,
        0x63, 0x75, 0x74, 0x69, 0x6f,
        0x6e, 0x21, 0x0a,
    };

    const page_size: u64 = 4096;

    try rawWrite(1, "[1] mmap: allocating RW memory...\n");
    const mem = try rawMmap(page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS);
    std.debug.print("[+] Allocated at 0x{x}\n", .{mem});

    try rawWrite(1, "[2] Writing Shellcode to allocated in memory...\n");
    const dest: [*]u8 = @ptrFromInt(mem);
    @memcpy(dest[0..shellcode.len], &shellcode);
    std.debug.print("[+] Wrote {d} bytes of shellcode\n", .{shellcode.len});

    try rawWrite(1, "[3] mprotect: RW -> RX (memory is now executable)...\n");
    try rawMprotect(mem, page_size, PROT_READ | PROT_EXEC);
    try rawWrite(1, "[+] Permission Changed!\n");

    try rawWrite(1, "[4] Jumping to shellcode...\n");
    const shellcode_fn: *const fn () callconv(.c) void = @ptrFromInt(mem);
    shellcode_fn();

    try rawWrite(1, "[5] munmap: freeing memory...");
    rawMunmap(mem, page_size);
    try rawWrite(1, "[+] Done!\n");
}
