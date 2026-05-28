//! Microbenchmarks for the helpers we've ported so far.
//!
//! Each benchmark auto-calibrates its iteration count to land in roughly
//! `target_total_ns`. We then run the calibrated batch several times to
//! collect a distribution.

const std = @import("std");
const ja4zig = @import("ja4zig");
const stats = @import("stats.zig");
const Stopwatch = @import("timer.zig").Stopwatch;

const Io = std.Io;

pub const Options = struct {
    /// Target time per measurement batch, in nanoseconds.
    target_per_batch_ns: i64 = 50 * std.time.ns_per_ms,
    /// Number of measurement batches per benchmark. The reported summary is
    /// over this many points.
    batches: usize = 30,
    /// Warmup batches that are discarded.
    warmup: usize = 3,
};

pub const Result = struct {
    name: []const u8,
    iters_per_batch: usize,
    /// Wall time per *iteration* — what you almost always want to look at.
    per_iter: stats.Summary,
    /// Throughput in operations per second, derived from `per_iter.median_ns`.
    ops_per_sec: f64,
    /// Optional throughput in bytes/sec (only set for benches that have a
    /// meaningful input size).
    bytes_per_sec: ?f64 = null,

    pub fn deinit(self: Result, gpa: std.mem.Allocator) void {
        gpa.free(self.name);
    }
};

/// Force the optimizer to keep the value alive — backed by an `asm volatile`
/// barrier (via `std.mem.doNotOptimizeAway`).
inline fn blackHole(x: anytype) void {
    std.mem.doNotOptimizeAway(x);
}

/// Launder a value through an `asm volatile` clobber so the optimizer
/// cannot see it as a known compile-time constant. Crucially for slices,
/// this also taints the memory the slice points to (via the "memory"
/// clobber) so calls that traverse the bytes can't be constant-folded.
inline fn opaque_(comptime T: type, x: T) T {
    var v = x;
    asm volatile (""
        :
        : [v] "m" (&v),
        : .{ .memory = true });
    return v;
}

fn calibrate(comptime body: anytype, io: Io, target_ns: i64) usize {
    var iters: usize = 1;
    while (true) {
        var sw = Stopwatch.begin(io);
        var i: usize = 0;
        while (i < iters) : (i += 1) body();
        const elapsed = sw.elapsedNs();
        if (elapsed >= target_ns) return iters;
        // Scale up, but cap the growth so a fast bench doesn't blow up
        // straight to billions of iters in one step.
        if (elapsed == 0) {
            iters *= 16;
        } else {
            const target_f = @as(f64, @floatFromInt(target_ns));
            const elapsed_f = @as(f64, @floatFromInt(elapsed));
            const factor: f64 = @max(2.0, @min(64.0, target_f / elapsed_f));
            const next_f: f64 = @as(f64, @floatFromInt(iters)) * factor;
            iters = @intFromFloat(next_f);
            if (iters == 0) iters = 1;
        }
        if (iters > 1_000_000_000) return iters; // safety stop
    }
}

fn measure(
    name: []const u8,
    comptime body: anytype,
    io: Io,
    gpa: std.mem.Allocator,
    opts: Options,
    bytes_per_iter: ?usize,
) !Result {
    const iters = calibrate(body, io, opts.target_per_batch_ns);

    // Warmup.
    var w: usize = 0;
    while (w < opts.warmup) : (w += 1) {
        var i: usize = 0;
        while (i < iters) : (i += 1) body();
    }

    var samples = try gpa.alloc(i64, opts.batches);
    defer gpa.free(samples);

    var b: usize = 0;
    while (b < opts.batches) : (b += 1) {
        var sw = Stopwatch.begin(io);
        var i: usize = 0;
        while (i < iters) : (i += 1) body();
        const elapsed = sw.elapsedNs();
        samples[b] = @divTrunc(elapsed, @as(i64, @intCast(iters)));
    }

    const summary = stats.Summary.compute(samples);
    const ops = if (summary.median_ns > 0)
        1_000_000_000.0 / @as(f64, @floatFromInt(summary.median_ns))
    else
        0.0;
    const bps: ?f64 = if (bytes_per_iter) |bpi|
        ops * @as(f64, @floatFromInt(bpi))
    else
        null;

    return .{
        .name = try gpa.dupe(u8, name),
        .iters_per_batch = iters,
        .per_iter = summary,
        .ops_per_sec = ops,
        .bytes_per_sec = bps,
    };
}

/// Run every microbenchmark and return their results. Caller owns the slice
/// and is responsible for calling `deinit` on each entry.
pub fn runAll(gpa: std.mem.Allocator, io: Io, opts: Options) ![]Result {
    var results: std.ArrayList(Result) = .empty;
    errdefer {
        for (results.items) |r| r.deinit(gpa);
        results.deinit(gpa);
    }

    // ── hash12: empty input ──────────────────────────────────────────────
    {
        const body = struct {
            fn run() void {
                var out: [12]u8 = undefined;
                const s = opaque_([]const u8, "");
                ja4zig.hash.hash12(s, &out);
                blackHole(out);
            }
        }.run;
        try results.append(gpa, try measure("hash12/empty", body, io, gpa, opts, 0));
    }

    // ── hash12: short input (typical JA4 cipher string) ──────────────────
    {
        const sample = "551d0f,551d25,551d11";
        const body = struct {
            fn run() void {
                var out: [12]u8 = undefined;
                const s = opaque_([]const u8, "551d0f,551d25,551d11");
                ja4zig.hash.hash12(s, &out);
                blackHole(out);
            }
        }.run;
        try results.append(
            gpa,
            try measure("hash12/short_20B", body, io, gpa, opts, sample.len),
        );
    }

    // ── hash12: realistic input (JA4 client hash input, ~256 B) ─────────
    {
        const big = "t13d1715h2_002f,0035,009c,009d,1301,1302,1303,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0015,0017,001c,0022,0023,002b,002d,0033,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201";
        const body = struct {
            fn run() void {
                var out: [12]u8 = undefined;
                const s = opaque_(
                    []const u8,
                    "t13d1715h2_002f,0035,009c,009d,1301,1302,1303,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0015,0017,001c,0022,0023,002b,002d,0033,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201",
                );
                ja4zig.hash.hash12(s, &out);
                blackHole(out);
            }
        }.run;
        try results.append(
            gpa,
            try measure("hash12/realistic_256B", body, io, gpa, opts, big.len),
        );
    }

    // ── hash12: 4 KiB input (stress) ─────────────────────────────────────
    {
        const big4k: [4096]u8 = comptime brk: {
            @setEvalBranchQuota(20_000);
            var buf: [4096]u8 = undefined;
            for (&buf, 0..) |*c, i| c.* = @intCast('a' + (i % 26));
            break :brk buf;
        };
        const body = struct {
            const data = big4k;
            fn run() void {
                var out: [12]u8 = undefined;
                const s = opaque_([]const u8, data[0..]);
                ja4zig.hash.hash12(s, &out);
                blackHole(out);
            }
        }.run;
        try results.append(gpa, try measure("hash12/4KiB", body, io, gpa, opts, 4096));
    }

    // ── parseVersion: happy path ─────────────────────────────────────────
    {
        const sample = "TShark (Wireshark) 4.0.8 (v4.0.8-0-g81696bb74857).";
        const body = struct {
            fn run() void {
                const s = opaque_(
                    []const u8,
                    "TShark (Wireshark) 4.0.8 (v4.0.8-0-g81696bb74857).",
                );
                const v = ja4zig.tshark.parseVersion(s);
                blackHole(v);
            }
        }.run;
        try results.append(
            gpa,
            try measure("parseVersion/happy", body, io, gpa, opts, sample.len),
        );
    }

    // ── parseVersion: no match (worst case) ──────────────────────────────
    {
        const body = struct {
            fn run() void {
                const s = opaque_([]const u8, "What the TShark?!");
                const v = ja4zig.tshark.parseVersion(s);
                blackHole(v);
            }
        }.run;
        try results.append(gpa, try measure("parseVersion/miss", body, io, gpa, opts, 0));
    }

    return try results.toOwnedSlice(gpa);
}
