//! End-to-end per-pcap benchmarks.
//!
//! For every fixture in `tests/testdata/pcap/`, measures wall-clock time to
//! produce JA4 fingerprints with each available implementation:
//!
//!   • ja4zig (this repo's binary)
//!   • rust   ja4 binary (cargo --release build under ../ja4/rust/target/release/ja4)
//!   • python ja4.py (../ja4/python/ja4.py)
//!   • tshark baseline (just `tshark -r <pcap> -T ek > /dev/null`) — gives a
//!     lower bound, since every other impl shells out to tshark.
//!
//! Any impl whose binary/script isn't found is silently skipped.

const std = @import("std");
const stats = @import("stats.zig");
const Stopwatch = @import("timer.zig").Stopwatch;

const Io = std.Io;

pub const Options = struct {
    runs: usize = 5,
    warmup: usize = 1,
    /// Skip pcaps larger than this many bytes. 0 = no cap.
    max_pcap_bytes: u64 = 0,
    /// Only run this implementation if non-null.
    only: ?Impl = null,
};

pub const Impl = enum {
    zig,
    rust,
    python,
    tshark,

    pub fn label(self: Impl) []const u8 {
        return switch (self) {
            .zig => "zig",
            .rust => "rust",
            .python => "python",
            .tshark => "tshark",
        };
    }
};

pub const PcapResult = struct {
    pcap_name: []const u8,
    pcap_bytes: u64,
    impl: Impl,
    /// null if the impl produced a non-zero exit (still reported in the
    /// output table, but with `--` in the time columns).
    summary: ?stats.Summary,
    /// Bytes processed per second, based on median time. null if failed.
    throughput: ?f64,

    pub fn deinit(self: PcapResult, gpa: std.mem.Allocator) void {
        gpa.free(self.pcap_name);
    }
};

const ImplCfg = struct {
    impl: Impl,
    /// argv template; `__PCAP__` is replaced with the pcap path. The slice
    /// itself is heap-allocated (gpa) — using `&.{...}` here is unsafe
    /// because the slice header lives on the constructor's stack frame.
    argv: []const []const u8,
};

fn allocTemplate(gpa: std.mem.Allocator, items: []const []const u8) ![]const []const u8 {
    const buf = try gpa.alloc([]const u8, items.len);
    @memcpy(buf, items);
    return buf;
}

fn buildArgv(
    gpa: std.mem.Allocator,
    template: []const []const u8,
    pcap_path: []const u8,
) ![]const []const u8 {
    var argv = try gpa.alloc([]const u8, template.len);
    for (template, 0..) |arg, i| {
        if (std.mem.eql(u8, arg, "__PCAP__")) {
            argv[i] = pcap_path;
        } else {
            argv[i] = arg;
        }
    }
    return argv;
}

fn fileExists(io: Io, path: []const u8) bool {
    var f = Io.Dir.cwd().openFile(io, path, .{}) catch return false;
    f.close(io);
    return true;
}

/// Returns a list of impls that are actually invokable on this machine.
fn detectImpls(
    gpa: std.mem.Allocator,
    io: Io,
    paths: ResolvedPaths,
) ![]ImplCfg {
    var out: std.ArrayList(ImplCfg) = .empty;
    errdefer out.deinit(gpa);

    // tshark — always include if on PATH (heuristic: we'll just try to run).
    try out.append(gpa, .{
        .impl = .tshark,
        .argv = try allocTemplate(gpa, &.{ "tshark", "-r", "__PCAP__", "-T", "ek" }),
    });

    // ja4zig — the executable from this repo.
    if (fileExists(io, paths.zig_exe)) {
        try out.append(gpa, .{
            .impl = .zig,
            .argv = try allocTemplate(gpa, &.{ paths.zig_exe, "__PCAP__" }),
        });
    }

    // rust ja4 release build (if present)
    if (fileExists(io, paths.rust_exe)) {
        try out.append(gpa, .{
            .impl = .rust,
            .argv = try allocTemplate(gpa, &.{ paths.rust_exe, "__PCAP__" }),
        });
    }

    // python ja4.py — call as `python3 path/to/ja4.py <pcap>`
    if (fileExists(io, paths.python_script)) {
        try out.append(gpa, .{
            .impl = .python,
            .argv = try allocTemplate(gpa, &.{ "python3", paths.python_script, "__PCAP__" }),
        });
    }

    return out.toOwnedSlice(gpa);
}

pub const ResolvedPaths = struct {
    pcap_dir: []const u8,
    zig_exe: []const u8,
    rust_exe: []const u8,
    python_script: []const u8,
};

pub fn runAll(
    gpa: std.mem.Allocator,
    io: Io,
    paths: ResolvedPaths,
    opts: Options,
) ![]PcapResult {
    const impls = try detectImpls(gpa, io, paths);
    defer {
        for (impls) |cfg| gpa.free(cfg.argv);
        gpa.free(impls);
    }

    if (impls.len == 0) {
        std.debug.print("[pcap-bench] no implementations detected\n", .{});
        return &.{};
    }

    var pcap_names: std.ArrayList([]u8) = .empty;
    defer {
        for (pcap_names.items) |n| gpa.free(n);
        pcap_names.deinit(gpa);
    }

    var pcap_dir = try Io.Dir.cwd().openDir(io, paths.pcap_dir, .{ .iterate = true });
    defer pcap_dir.close(io);

    var it = pcap_dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (std.mem.indexOf(u8, entry.name, ".pcap") == null) continue;
        try pcap_names.append(gpa, try gpa.dupe(u8, entry.name));
    }
    std.mem.sort([]u8, pcap_names.items, {}, struct {
        fn lt(_: void, a: []u8, b: []u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lt);

    var results: std.ArrayList(PcapResult) = .empty;
    errdefer {
        for (results.items) |r| r.deinit(gpa);
        results.deinit(gpa);
    }

    var samples = try gpa.alloc(i64, opts.runs);
    defer gpa.free(samples);

    for (pcap_names.items) |name| {
        const pcap_path = try std.fs.path.join(gpa, &.{ paths.pcap_dir, name });
        defer gpa.free(pcap_path);

        const pcap_bytes: u64 = blk: {
            const st = pcap_dir.statFile(io, name, .{}) catch break :blk 0;
            break :blk st.size;
        };
        if (opts.max_pcap_bytes != 0 and pcap_bytes > opts.max_pcap_bytes) continue;

        for (impls) |cfg| {
            if (opts.only) |only| if (cfg.impl != only) continue;

            const argv = try buildArgv(gpa, cfg.argv, pcap_path);
            defer gpa.free(argv);

            // Warmup.
            var w: usize = 0;
            while (w < opts.warmup) : (w += 1) {
                _ = runOnce(gpa, io, argv) catch {};
            }

            var any_failed = false;
            var i: usize = 0;
            while (i < opts.runs) : (i += 1) {
                const elapsed = runOnce(gpa, io, argv) catch |err| {
                    std.debug.print(
                        "[pcap-bench] {s}/{s}: run {d} failed: {s}\n",
                        .{ cfg.impl.label(), name, i, @errorName(err) },
                    );
                    any_failed = true;
                    samples[i] = 0;
                    continue;
                };
                samples[i] = elapsed;
            }

            const summary: ?stats.Summary = if (any_failed)
                null
            else
                stats.Summary.compute(samples);
            const throughput: ?f64 = if (summary) |s|
                if (s.median_ns > 0)
                    @as(f64, @floatFromInt(pcap_bytes)) * 1e9 / @as(f64, @floatFromInt(s.median_ns))
                else
                    null
            else
                null;

            try results.append(gpa, .{
                .pcap_name = try gpa.dupe(u8, name),
                .pcap_bytes = pcap_bytes,
                .impl = cfg.impl,
                .summary = summary,
                .throughput = throughput,
            });
        }
    }

    return results.toOwnedSlice(gpa);
}

/// Runs `argv` to completion, discarding stdout/stderr, returns elapsed ns.
/// Returns an error if the process couldn't be launched OR if it exited
/// non-zero (so failed impls show up as failures rather than fast successes).
fn runOnce(gpa: std.mem.Allocator, io: Io, argv: []const []const u8) !i64 {
    var sw = Stopwatch.begin(io);
    const result = try std.process.run(gpa, io, .{
        .argv = argv,
        .expand_arg0 = .expand,
    });
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);
    const elapsed = sw.elapsedNs();
    switch (result.term) {
        .exited => |code| if (code != 0) return error.ChildFailed,
        else => return error.ChildSignalled,
    }
    return elapsed;
}
