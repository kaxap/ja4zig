const std = @import("std");
const Io = std.Io;

/// Phase 1 stub: the binary exists so the snapshot test harness has something
/// to invoke and `zig build` succeeds, but no fingerprints are computed yet.
/// Subsequent phases will replace this with the real CLI.
pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var stderr_buffer: [256]u8 = undefined;
    var stderr_file_writer: Io.File.Writer = .init(.stderr(), io, &stderr_buffer);
    const stderr_writer = &stderr_file_writer.interface;
    try stderr_writer.print(
        "ja4zig: not implemented yet (phase 1 — test harness only)\n",
        .{},
    );
    try stderr_writer.flush();

    std.process.exit(2);
}
