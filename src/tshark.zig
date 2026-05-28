const std = @import("std");

/// Parses the version number from the first line of `tshark --version` output.
///
/// The first line looks like:
///   `TShark (Wireshark) 4.0.8 (v4.0.8-0-g81696bb74857).`
///
/// Mirrors `parse_tshark_version` in `rust/ja4/src/lib.rs`.
///
/// Implementation notes (optimized):
///   • The 2-byte `") "` marker used to be matched via `std.mem.indexOf`,
///     which falls back to a generic Boyer-Moore-style scan. We now find `)`
///     with `indexOfScalarPos` (SIMD-vectorized on x86_64 and AArch64) and
///     only confirm the trailing space, restarting if not.
///   • The whitespace scan uses a single-character switch (compiles to a
///     compact compare-tree); the trailing-dot stripping is folded into the
///     final slice computation so there's no second pass.
pub fn parseVersion(output: []const u8) ?[]const u8 {
    // Locate ") " — scan for ')' first because indexOfScalar has a fast
    // SIMD path, then bounds-check + verify the next byte is a space. If a
    // bare ')' is found in the middle of nowhere we keep searching.
    var search_from: usize = 0;
    const value_start = while (true) {
        const close_idx = std.mem.indexOfScalarPos(u8, output, search_from, ')') orelse return null;
        if (close_idx + 1 < output.len and output[close_idx + 1] == ' ') {
            break close_idx + 2;
        }
        search_from = close_idx + 1;
    };

    // Scan version body until whitespace or end-of-string.
    var end = value_start;
    while (end < output.len) : (end += 1) {
        switch (output[end]) {
            ' ', '\t', '\n', '\r' => break,
            else => {},
        }
    }

    // Match the upstream Rust contract: we require *some* whitespace
    // terminator. Hitting EOF means we don't trust the version string.
    if (end == output.len) return null;
    if (end == value_start) return null;

    // Strip an optional trailing '.' without a second pass.
    const stop = if (output[end - 1] == '.') end - 1 else end;
    return output[value_start..stop];
}

test "parseVersion typical" {
    try std.testing.expectEqualStrings(
        "4.0.8",
        parseVersion("TShark (Wireshark) 4.0.8 (v4.0.8-0-g81696bb74857).").?,
    );
}

test "parseVersion legacy format" {
    try std.testing.expectEqualStrings(
        "3.6.2",
        parseVersion("TShark (Wireshark) 3.6.2 (Git v3.6.2 packaged as 3.6.2-2)").?,
    );
}

test "parseVersion trailing newline copyright" {
    try std.testing.expectEqualStrings(
        "4.4.0",
        parseVersion("TShark (Wireshark) 4.4.0.\n\nCopyright 1998-2024").?,
    );
}

test "parseVersion abrupt end returns null" {
    try std.testing.expect(parseVersion("TShark (Wireshark) 4.4.0.") == null);
}

test "parseVersion garbage returns null" {
    try std.testing.expect(parseVersion("What the TShark?!") == null);
}

test "parseVersion lone ')' before the real marker" {
    // A `)` that isn't followed by space shouldn't trick us — we should
    // keep scanning for the real `") "`.
    try std.testing.expectEqualStrings(
        "4.0.0",
        parseVersion("foo)bar (Wireshark) 4.0.0 (rest)").?,
    );
}
