const std = @import("std");

/// Parses the version number from the first line of `tshark --version` output.
///
/// The first line looks like:
///   `TShark (Wireshark) 4.0.8 (v4.0.8-0-g81696bb74857).`
///
/// Mirrors `parse_tshark_version` in `rust/ja4/src/lib.rs`.
pub fn parseVersion(output: []const u8) ?[]const u8 {
    const marker = ") ";
    const start_idx = std.mem.indexOf(u8, output, marker) orelse return null;
    const after = output[start_idx + marker.len ..];
    var end: usize = 0;
    while (end < after.len) : (end += 1) {
        const c = after[end];
        if (c == ' ' or c == '\t' or c == '\n' or c == '\r') break;
    }
    if (end == 0 or end == after.len) return null;
    var ver = after[0..end];
    if (ver.len > 0 and ver[ver.len - 1] == '.') ver = ver[0 .. ver.len - 1];
    return ver;
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
