const std = @import("std");

/// Returns the first 12 hex characters of the SHA-256 digest of `s`.
/// Returns `"000000000000"` if `s` is empty.
///
/// Mirrors `hash12` in `rust/ja4/src/lib.rs`.
pub fn hash12(s: []const u8, out: *[12]u8) void {
    if (s.len == 0) {
        @memcpy(out, "000000000000");
        return;
    }
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(s, &digest, .{});
    // hex-encode the first 6 bytes → 12 hex chars
    const hex = "0123456789abcdef";
    for (digest[0..6], 0..) |b, i| {
        out[i * 2] = hex[b >> 4];
        out[i * 2 + 1] = hex[b & 0x0f];
    }
}

test "hash12 known vector" {
    var buf: [12]u8 = undefined;
    hash12("551d0f,551d25,551d11", &buf);
    try std.testing.expectEqualStrings("aae71e8db6d7", &buf);
}

test "hash12 empty" {
    var buf: [12]u8 = undefined;
    hash12("", &buf);
    try std.testing.expectEqualStrings("000000000000", &buf);
}
