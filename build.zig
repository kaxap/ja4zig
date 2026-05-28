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

    // ─── Benchmark suite ──────────────────────────────────────────────────
    //
    // Builds a separate `ja4zig-bench` executable that drives microbenchmarks
    // for the ported helpers plus per-pcap end-to-end timings against every
    // implementation we can find on disk (rust, python, tshark baseline,
    // plus the ja4zig stub).
    //
    // Run with: `zig build bench` (forwards extra args via `--`).
    // Default optimization for benches is ReleaseFast — it's almost always
    // what you want, and a Debug build of the hash benches is meaningless.

    const bench_optimize = b.option(
        std.builtin.OptimizeMode,
        "bench-optimize",
        "Optimization mode for the benchmark binary (default: ReleaseFast)",
    ) orelse .ReleaseFast;

    const bench_opts = b.addOptions();
    bench_opts.addOption([]const u8, "default_pcap_dir", b.pathFromRoot("tests/testdata/pcap"));
    // Locate the ja4zig binary in zig-out/bin/ja4 after the default install
    // step runs. Users can still override via --zig-exe=...
    bench_opts.addOption([]const u8, "default_zig_exe", b.pathJoin(&.{ b.install_path, "bin", "ja4" }));
    bench_opts.addOption([]const u8, "default_rust_exe", b.pathFromRoot("../ja4/rust/target/release/ja4"));
    bench_opts.addOption([]const u8, "default_python_script", b.pathFromRoot("../ja4/python/ja4.py"));

    const bench_mod = b.createModule(.{
        .root_source_file = b.path("bench/main.zig"),
        .target = target,
        .optimize = bench_optimize,
        .imports = &.{
            .{ .name = "ja4zig", .module = ja4_mod },
        },
    });
    bench_mod.addOptions("build_options", bench_opts);

    const bench_exe = b.addExecutable(.{
        .name = "ja4zig-bench",
        .root_module = bench_mod,
    });
    b.installArtifact(bench_exe);

    const bench_step = b.step("bench", "Run the benchmark suite");
    const run_bench = b.addRunArtifact(bench_exe);
    // Benches invoke the ja4 binary, so make sure it's built and installed
    // first (so `zig-out/bin/ja4` exists at the path we baked in).
    run_bench.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_bench.addArgs(args);
    bench_step.dependOn(&run_bench.step);

    // Tests for the bench helpers (stats module).
    const bench_tests_mod = b.createModule(.{
        .root_source_file = b.path("bench/stats.zig"),
        .target = target,
    });
    const bench_tests = b.addTest(.{ .root_module = bench_tests_mod });
    const run_bench_tests = b.addRunArtifact(bench_tests);
    test_step.dependOn(&run_bench_tests.step);
}
