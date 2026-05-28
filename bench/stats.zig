//! Statistical helpers for benchmark reporting.
//!
//! All durations are in nanoseconds (i64). Mean is in floating point because
//! we need it for stddev; everything else (median, percentiles) stays in
//! integer ns to avoid rounding noise in the table output.

const std = @import("std");

pub const Summary = struct {
    n: usize,
    min_ns: i64,
    max_ns: i64,
    mean_ns: f64,
    median_ns: i64,
    p95_ns: i64,
    stddev_ns: f64,
    /// Coefficient of variation = stddev / mean. A rough handle on
    /// reproducibility — anything above ~10% means the bench is noisy.
    cv: f64,

    pub fn compute(samples: []i64) Summary {
        std.debug.assert(samples.len > 0);
        std.mem.sort(i64, samples, {}, std.sort.asc(i64));

        var sum: i128 = 0;
        for (samples) |s| sum += s;
        const mean: f64 = @as(f64, @floatFromInt(@as(i64, @intCast(sum)))) / @as(f64, @floatFromInt(samples.len));

        var sq_err_sum: f64 = 0.0;
        for (samples) |s| {
            const d = @as(f64, @floatFromInt(s)) - mean;
            sq_err_sum += d * d;
        }
        const variance = if (samples.len > 1)
            sq_err_sum / @as(f64, @floatFromInt(samples.len - 1))
        else
            0.0;
        const stddev = @sqrt(variance);

        const median = samples[samples.len / 2];
        // Nearest-rank p95.
        const p95_idx = blk: {
            const idx: usize = @intFromFloat(@ceil(0.95 * @as(f64, @floatFromInt(samples.len))));
            break :blk if (idx == 0) 0 else idx - 1;
        };

        return .{
            .n = samples.len,
            .min_ns = samples[0],
            .max_ns = samples[samples.len - 1],
            .mean_ns = mean,
            .median_ns = median,
            .p95_ns = samples[p95_idx],
            .stddev_ns = stddev,
            .cv = if (mean > 0.0) stddev / mean else 0.0,
        };
    }
};

/// Formats a nanosecond count with adaptive units (ns/µs/ms/s).
pub fn formatDuration(w: *std.Io.Writer, ns: f64) std.Io.Writer.Error!void {
    if (ns < 1_000.0) {
        try w.print("{d:>7.1}ns", .{ns});
    } else if (ns < 1_000_000.0) {
        try w.print("{d:>7.2}µs", .{ns / 1_000.0});
    } else if (ns < 1_000_000_000.0) {
        try w.print("{d:>7.2}ms", .{ns / 1_000_000.0});
    } else {
        try w.print("{d:>7.3}s ", .{ns / 1_000_000_000.0});
    }
}

test "summary basic" {
    var samples = [_]i64{ 10, 20, 30, 40, 50 };
    const s = Summary.compute(&samples);
    try std.testing.expectEqual(@as(i64, 10), s.min_ns);
    try std.testing.expectEqual(@as(i64, 50), s.max_ns);
    try std.testing.expectEqual(@as(i64, 30), s.median_ns);
    try std.testing.expectApproxEqAbs(@as(f64, 30.0), s.mean_ns, 1e-9);
}
