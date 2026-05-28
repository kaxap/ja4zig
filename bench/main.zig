//! Benchmark runner entry point.
//!
//! Usage:
//!   ja4zig-bench [micro|pcap|all] [--runs=N] [--batches=N] [--json]
//!                [--impl=zig|rust|python|tshark]
//!                [--pcap-dir=PATH] [--zig-exe=PATH]
//!                [--rust-exe=PATH] [--python-script=PATH]
//!
//! Defaults are set up so `zig build bench` Just Works on this checkout —
//! see `build.zig`, which wires the in-tree paths through compile-time
//! options.

const std = @import("std");
const Io = std.Io;

const micro = @import("micro.zig");
const pcap_bench = @import("pcap_bench.zig");
const output = @import("output.zig");
const build_options = @import("build_options");

const Mode = enum { micro, pcap, all };

const Args = struct {
    mode: Mode = .all,
    runs: usize = 5,
    warmup: usize = 1,
    batches: usize = 30,
    micro_warmup: usize = 3,
    target_batch_ms: i64 = 50,
    json: bool = false,
    only: ?pcap_bench.Impl = null,
    max_pcap_bytes: u64 = 0,

    pcap_dir: []const u8,
    zig_exe: []const u8,
    rust_exe: []const u8,
    python_script: []const u8,
};

fn parseArgs(arena: std.mem.Allocator, argv: []const []const u8) !Args {
    var a: Args = .{
        .pcap_dir = build_options.default_pcap_dir,
        .zig_exe = build_options.default_zig_exe,
        .rust_exe = build_options.default_rust_exe,
        .python_script = build_options.default_python_script,
    };

    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (std.mem.eql(u8, arg, "micro")) {
            a.mode = .micro;
        } else if (std.mem.eql(u8, arg, "pcap")) {
            a.mode = .pcap;
        } else if (std.mem.eql(u8, arg, "all")) {
            a.mode = .all;
        } else if (std.mem.startsWith(u8, arg, "--runs=")) {
            a.runs = try std.fmt.parseInt(usize, arg["--runs=".len..], 10);
        } else if (std.mem.startsWith(u8, arg, "--warmup=")) {
            a.warmup = try std.fmt.parseInt(usize, arg["--warmup=".len..], 10);
        } else if (std.mem.startsWith(u8, arg, "--batches=")) {
            a.batches = try std.fmt.parseInt(usize, arg["--batches=".len..], 10);
        } else if (std.mem.startsWith(u8, arg, "--target-batch-ms=")) {
            a.target_batch_ms = try std.fmt.parseInt(i64, arg["--target-batch-ms=".len..], 10);
        } else if (std.mem.eql(u8, arg, "--json")) {
            a.json = true;
        } else if (std.mem.startsWith(u8, arg, "--max-pcap-bytes=")) {
            a.max_pcap_bytes = try std.fmt.parseInt(u64, arg["--max-pcap-bytes=".len..], 10);
        } else if (std.mem.startsWith(u8, arg, "--impl=")) {
            const v = arg["--impl=".len..];
            a.only = if (std.mem.eql(u8, v, "zig")) .zig else if (std.mem.eql(u8, v, "rust")) .rust else if (std.mem.eql(u8, v, "python")) .python else if (std.mem.eql(u8, v, "tshark")) .tshark else return error.UnknownImpl;
        } else if (std.mem.startsWith(u8, arg, "--pcap-dir=")) {
            a.pcap_dir = try arena.dupe(u8, arg["--pcap-dir=".len..]);
        } else if (std.mem.startsWith(u8, arg, "--zig-exe=")) {
            a.zig_exe = try arena.dupe(u8, arg["--zig-exe=".len..]);
        } else if (std.mem.startsWith(u8, arg, "--rust-exe=")) {
            a.rust_exe = try arena.dupe(u8, arg["--rust-exe=".len..]);
        } else if (std.mem.startsWith(u8, arg, "--python-script=")) {
            a.python_script = try arena.dupe(u8, arg["--python-script=".len..]);
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            try printHelp();
            std.process.exit(0);
        } else {
            std.debug.print("unknown argument: {s}\n", .{arg});
            try printHelp();
            std.process.exit(2);
        }
    }
    return a;
}

fn printHelp() !void {
    const txt =
        \\ja4zig-bench — extensive benchmarks for the JA4 Zig port
        \\
        \\Usage:
        \\  ja4zig-bench [micro|pcap|all] [options]
        \\
        \\Modes:
        \\  micro    Microbenchmarks for ported helpers (hash12, parseVersion).
        \\  pcap     End-to-end per-pcap timings across all detected impls.
        \\  all      Both (default).
        \\
        \\Common options:
        \\  --json                 Emit JSON to stdout in addition to the table.
        \\  --runs=N               Per-pcap iterations (default 5).
        \\  --warmup=N             Per-pcap warmup runs (default 1).
        \\  --batches=N            Micro measurement batches (default 30).
        \\  --target-batch-ms=N    Target ms per micro batch (default 50).
        \\  --impl=zig|rust|python|tshark   Only benchmark one impl.
        \\  --max-pcap-bytes=N     Skip pcaps larger than N bytes (0 = no cap).
        \\
        \\Paths (defaults baked at build time):
        \\  --pcap-dir=PATH        Directory of pcap fixtures.
        \\  --zig-exe=PATH         ja4zig binary to benchmark.
        \\  --rust-exe=PATH        Upstream rust ja4 release binary.
        \\  --python-script=PATH   Upstream python ja4.py.
        \\
    ;
    std.debug.print("{s}", .{txt});
}

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const io = init.io;

    const argv = try init.minimal.args.toSlice(arena);
    const args = try parseArgs(arena, argv);
    // Convert ms to ns for the micro options.
    const micro_opts: micro.Options = .{
        .target_per_batch_ns = args.target_batch_ms * std.time.ns_per_ms,
        .batches = args.batches,
        .warmup = args.micro_warmup,
    };
    const pcap_opts: pcap_bench.Options = .{
        .runs = args.runs,
        .warmup = args.warmup,
        .max_pcap_bytes = args.max_pcap_bytes,
        .only = args.only,
    };

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;

    var stderr_buffer: [1024]u8 = undefined;
    var stderr_file_writer: Io.File.Writer = .init(.stderr(), io, &stderr_buffer);
    const stderr = &stderr_file_writer.interface;
    defer stderr.flush() catch {};

    try stderr.print(
        "ja4zig-bench: mode={s} runs={d} batches={d} pcap_dir={s}\n",
        .{ @tagName(args.mode), args.runs, args.batches, args.pcap_dir },
    );
    try stderr.flush();

    var micro_results: []micro.Result = &.{};
    defer {
        for (micro_results) |r| r.deinit(arena);
        if (micro_results.len > 0) arena.free(micro_results);
    }
    var pcap_results: []pcap_bench.PcapResult = &.{};
    defer {
        for (pcap_results) |r| r.deinit(arena);
        if (pcap_results.len > 0) arena.free(pcap_results);
    }

    if (args.mode == .micro or args.mode == .all) {
        try stderr.print("running microbenchmarks (target={d}ms × {d} batches)...\n", .{
            args.target_batch_ms,
            args.batches,
        });
        try stderr.flush();
        micro_results = try micro.runAll(arena, io, micro_opts);
        if (!args.json) {
            try output.writeMicroTable(stdout, micro_results);
            try stdout.flush();
        }
    }

    if (args.mode == .pcap or args.mode == .all) {
        try stderr.print("running per-pcap benchmarks ({d} runs each)...\n", .{args.runs});
        try stderr.flush();
        pcap_results = try pcap_bench.runAll(arena, io, .{
            .pcap_dir = args.pcap_dir,
            .zig_exe = args.zig_exe,
            .rust_exe = args.rust_exe,
            .python_script = args.python_script,
        }, pcap_opts);
        if (!args.json) {
            try output.writePcapTable(stdout, pcap_results);
            try stdout.flush();
        }
    }

    if (args.json) {
        try output.writeJson(stdout, micro_results, pcap_results);
        try stdout.flush();
    }
}
