const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Library module (re-exported helpers; used by unit tests).
    const ja4_mod = b.addModule("ja4zig", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });

    // CLI executable.
    const exe = b.addExecutable(.{
        .name = "ja4",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ja4zig", .module = ja4_mod },
            },
        }),
    });
    b.installArtifact(exe);

    // `zig build run -- <args...>`
    const run_step = b.step("run", "Run the ja4 CLI");
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    run_step.dependOn(&run_cmd.step);

    // ─── Tests ────────────────────────────────────────────────────────────
    //
    // Two layers:
    //  • Unit tests embedded in src/*.zig (run via the library module).
    //  • The snapshot test harness in tests/snapshot_test.zig — invokes the
    //    locally-built ja4 binary against every pcap fixture and diffs the
    //    output against tests/testdata/snapshots/<name>.yaml.

    const lib_tests = b.addTest(.{ .root_module = ja4_mod });
    const run_lib_tests = b.addRunArtifact(lib_tests);

    // Pass paths to the snapshot harness via a build_options module.
    const snapshot_opts = b.addOptions();
    snapshot_opts.addOptionPath("exe_path", exe.getEmittedBin());
    snapshot_opts.addOptionPath("pcap_dir", b.path("tests/testdata/pcap"));
    snapshot_opts.addOptionPath("snapshots_dir", b.path("tests/testdata/snapshots"));

    const snapshot_mod = b.createModule(.{
        .root_source_file = b.path("tests/snapshot_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    snapshot_mod.addOptions("build_options", snapshot_opts);

    const snapshot_tests = b.addTest(.{ .root_module = snapshot_mod });
    // Build the exe before running the snapshot harness.
    snapshot_tests.step.dependOn(&exe.step);
    const run_snapshot_tests = b.addRunArtifact(snapshot_tests);

    const test_step = b.step("test", "Run unit + snapshot tests");
    test_step.dependOn(&run_lib_tests.step);
    test_step.dependOn(&run_snapshot_tests.step);
}
