const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const implant = b.addExecutable(.{
        .name = "implant",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(implant);

    const run_implant = b.addRunArtifact(implant);
    run_implant.step.dependOn(b.getInstallStep());
    const run_step = b.step("run", "Run the implant directly");
    run_step.dependOn(&run_implant.step);

    const loader = b.addExecutable(.{
        .name = "loader",
        .root_module = b.createModule(.{
            .root_source_file = b.path("loader/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    loader.root_module.addAnonymousImport("implant", .{
        .root_source_file = b.path("zig-out/bin/implant"),
    });

    const install_loader = b.addInstallArtifact(loader, .{});
    const loader_step = b.step("loader", "Build the fileless loader");
    loader_step.dependOn(&install_loader.step);

    const run_loader = b.addRunArtifact(loader);
    run_loader.step.dependOn(&install_loader.step);
    const run_loader_step = b.step("run-loader", "Run via fileless loader");
    run_loader_step.dependOn(&run_loader.step);
}
