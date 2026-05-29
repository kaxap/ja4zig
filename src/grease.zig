//! TLS GREASE value detection (RFC 8701) — shared by tls.zig and pcap parsing.

const std = @import("std");

// `0x0a0a, 0x1a1a, 0x2a2a, ..., 0xfafa`.
pub fn isGreaseInt(v: u32) bool {
    if (v > 0xffff) return false;
    const hi: u8 = @intCast((v >> 8) & 0xff);
    const lo: u8 = @intCast(v & 0xff);
    return hi == lo and (hi & 0x0f) == 0x0a;
}

/// Matches the hex-string form tshark emits for supported_version values:
/// `"0x0a0a"` … `"0xfafa"`.
pub fn isGreaseHexStr(s: []const u8) bool {
    if (s.len != 6) return false;
    if (s[0] != '0' or (s[1] != 'x' and s[1] != 'X')) return false;
    if (s[2] != s[4] or s[3] != s[5]) return false;
    return s[3] == 'a' or s[3] == 'A';
}

test "GREASE ints" {
    try std.testing.expect(isGreaseInt(0x0a0a));
    try std.testing.expect(isGreaseInt(0xfafa));
    try std.testing.expect(!isGreaseInt(0x1301));
    try std.testing.expect(!isGreaseInt(0x0000));
}

test "GREASE hex strings" {
    try std.testing.expect(isGreaseHexStr("0x0a0a"));
    try std.testing.expect(isGreaseHexStr("0xfafa"));
    try std.testing.expect(!isGreaseHexStr("0x0303"));
    try std.testing.expect(!isGreaseHexStr("0x0a0b"));
}
