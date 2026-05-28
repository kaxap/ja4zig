//! Table & JSON formatting for bench results.

const std = @import("std");
const stats = @import("stats.zig");
const micro = @import("micro.zig");
const pcap_bench = @import("pcap_bench.zig");

const Io = std.Io;

pub fn writeMicroTable(w: *Io.Writer, results: []const micro.Result) !void {
    try w.print("\n=== microbenchmarks ===\n", .{});
    try w.print(
        "{s:<26} {s:>11} {s:>11} {s:>11} {s:>11} {s:>6} {s:>13} {s:>12}\n",
        .{ "bench", "min", "median", "mean", "p95", "cv%", "ops/s", "throughput" },
    );
    var dashes_buf: [110]u8 = undefined;
    @memset(&dashes_buf, '-');
    try w.print("{s}\n", .{&dashes_buf});

    for (results) |r| {
        try w.print("{s:<26} ", .{r.name});
        try stats.formatDuration(w, @floatFromInt(r.per_iter.min_ns));
        try w.print("  ", .{});
        try stats.formatDuration(w, @floatFromInt(r.per_iter.median_ns));
        try w.print("  ", .{});
        try stats.formatDuration(w, r.per_iter.mean_ns);
        try w.print("  ", .{});
        try stats.formatDuration(w, @floatFromInt(r.per_iter.p95_ns));
        try w.print(" {d:>5.1}% ", .{r.per_iter.cv * 100.0});
        try w.print("{d:>12.3}M ", .{r.ops_per_sec / 1_000_000.0});
        if (r.bytes_per_sec) |bps| {
            try w.print("{d:>9.2} MB/s\n", .{bps / (1024.0 * 1024.0)});
        } else {
            try w.print("{s:>12}\n", .{"—"});
        }
    }
}

pub fn writePcapTable(w: *Io.Writer, results: []const pcap_bench.PcapResult) !void {
    try w.print("\n=== per-pcap end-to-end ===\n", .{});
    try w.print(
        "{s:<46} {s:>8} {s:<7} {s:>11} {s:>11} {s:>11} {s:>6} {s:>11}\n",
        .{ "pcap", "size", "impl", "min", "median", "p95", "cv%", "throughput" },
    );

    for (results) |r| {
        try w.print("{s:<46} ", .{truncate(r.pcap_name, 46)});
        try writePrettyBytes(w, r.pcap_bytes, 8);
        try w.print(" ", .{});
        try w.print("{s:<7} ", .{r.impl.label()});
        if (r.summary) |s| {
            try stats.formatDuration(w, @floatFromInt(s.min_ns));
            try w.print("  ", .{});
            try stats.formatDuration(w, @floatFromInt(s.median_ns));
            try w.print("  ", .{});
            try stats.formatDuration(w, @floatFromInt(s.p95_ns));
            try w.print(" {d:>5.1}% ", .{s.cv * 100.0});
            if (r.throughput) |tp| {
                try w.print("{d:>7.2} MB/s\n", .{tp / (1024.0 * 1024.0)});
            } else {
                try w.print("{s:>11}\n", .{"—"});
            }
        } else {
            try w.print("{s:>11} {s:>11} {s:>11} {s:>6} {s:>11}\n", .{ "—", "FAIL", "—", "—", "—" });
        }
    }
}

pub fn writeJson(
    w: *Io.Writer,
    micro_results: []const micro.Result,
    pcap_results: []const pcap_bench.PcapResult,
) !void {
    try w.print("{{\n  \"micro\": [\n", .{});
    for (micro_results, 0..) |r, i| {
        try w.print(
            "    {{\"name\": \"{s}\", \"iters_per_batch\": {d}, " ++
                "\"min_ns\": {d}, \"median_ns\": {d}, \"mean_ns\": {d:.3}, " ++
                "\"p95_ns\": {d}, \"max_ns\": {d}, \"stddev_ns\": {d:.3}, " ++
                "\"cv\": {d:.6}, \"ops_per_sec\": {d:.3}",
            .{
                r.name,                 r.iters_per_batch, r.per_iter.min_ns,
                r.per_iter.median_ns,   r.per_iter.mean_ns,
                r.per_iter.p95_ns,      r.per_iter.max_ns, r.per_iter.stddev_ns,
                r.per_iter.cv,          r.ops_per_sec,
            },
        );
        if (r.bytes_per_sec) |bps| {
            try w.print(", \"bytes_per_sec\": {d:.3}", .{bps});
        }
        try w.print("}}{s}\n", .{if (i + 1 == micro_results.len) "" else ","});
    }
    try w.print("  ],\n  \"pcap\": [\n", .{});

    for (pcap_results, 0..) |r, i| {
        try w.print(
            "    {{\"pcap\": \"{s}\", \"size\": {d}, \"impl\": \"{s}\"",
            .{ r.pcap_name, r.pcap_bytes, r.impl.label() },
        );
        if (r.summary) |s| {
            try w.print(
                ", \"min_ns\": {d}, \"median_ns\": {d}, \"mean_ns\": {d:.3}, " ++
                    "\"p95_ns\": {d}, \"max_ns\": {d}, \"stddev_ns\": {d:.3}, \"cv\": {d:.6}",
                .{ s.min_ns, s.median_ns, s.mean_ns, s.p95_ns, s.max_ns, s.stddev_ns, s.cv },
            );
        } else {
            try w.print(", \"failed\": true", .{});
        }
        if (r.throughput) |tp| {
            try w.print(", \"throughput_bps\": {d:.3}", .{tp});
        }
        try w.print("}}{s}\n", .{if (i + 1 == pcap_results.len) "" else ","});
    }
    try w.print("  ]\n}}\n", .{});
}

fn truncate(s: []const u8, max: usize) []const u8 {
    return if (s.len <= max) s else s[0..max];
}

/// Formats `n` as a short human-readable byte count into a writer instead of
/// returning a slice over a static buffer (the previous implementation was
/// not reentrant — calling it twice in a single `print` call clobbered the
/// earlier result).
fn writePrettyBytes(w: *std.Io.Writer, n: u64, comptime width: comptime_int) !void {
    if (n < 1024) {
        try w.print("{d:>" ++ std.fmt.comptimePrint("{d}", .{width}) ++ "}", .{n});
    } else if (n < 1024 * 1024) {
        try w.print(
            "{d:>" ++ std.fmt.comptimePrint("{d}", .{width - 1}) ++ ".1}K",
            .{@as(f64, @floatFromInt(n)) / 1024.0},
        );
    } else {
        try w.print(
            "{d:>" ++ std.fmt.comptimePrint("{d}", .{width - 1}) ++ ".1}M",
            .{@as(f64, @floatFromInt(n)) / (1024.0 * 1024.0)},
        );
    }
}
