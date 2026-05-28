//! Thin wrapper around `std.Io.Clock.awake` so the rest of the bench
//! suite doesn't have to thread `io` and `clock` through everything.

const std = @import("std");

pub const Stopwatch = struct {
    io: std.Io,
    start: std.Io.Clock.Timestamp,

    pub fn begin(io: std.Io) Stopwatch {
        return .{
            .io = io,
            .start = std.Io.Clock.Timestamp.now(io, .awake),
        };
    }

    /// Elapsed nanoseconds since `begin`.
    pub fn elapsedNs(s: Stopwatch) i64 {
        const now = std.Io.Clock.Timestamp.now(s.io, .awake);
        return @intCast(s.start.durationTo(now).raw.toNanoseconds());
    }

    pub fn reset(s: *Stopwatch) void {
        s.start = std.Io.Clock.Timestamp.now(s.io, .awake);
    }
};
