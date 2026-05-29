//! JA4T — TCP SYN fingerprint. Matches `rust/ja4/src/tcp.rs`.

const std = @import("std");
const pcap = @import("pcap.zig");

pub const ClientStats = struct {
    pkt_num: pcap.PacketNum,
    window_size: u16,
    /// Owned. TCP option kinds in occurrence order.
    options: []u8,
    mss: ?u16,
    window_scale: ?u8,
};

pub const State = struct {
    client: ?ClientStats = null,

    pub fn deinit(self: *State, gpa: std.mem.Allocator) void {
        if (self.client) |c| gpa.free(c.options);
        self.* = .{};
    }
};

/// Process one packet. Captures the FIRST initial SYN (SYN=1, ACK=0).
pub fn update(state: *State, pkt: pcap.Packet, gpa: std.mem.Allocator) !void {
    if (state.client != null) return; // already captured

    const tcp = pkt.findProto("tcp") orelse return;
    const flags_str = tcp.first("tcp.flags") orelse return;
    // tshark `-T ek` emits the raw integer (decimal). PDML/json mode would
    // emit `"0x00c2"`; accept both shapes.
    const flags = parseIntFlexible(u16, flags_str) catch return;
    if (!isInitialSyn(flags)) return;

    const window_size = blk: {
        const s = tcp.first("tcp.window_size_value") orelse break :blk @as(?u16, null);
        break :blk @as(?u16, std.fmt.parseInt(u16, s, 10) catch break :blk null);
    };
    if (window_size == null) return;

    var opts: std.ArrayList(u8) = .empty;
    errdefer opts.deinit(gpa);
    var it = tcp.values("tcp.option_kind");
    while (it.next()) |v| {
        const k = std.fmt.parseInt(u8, v, 10) catch continue;
        try opts.append(gpa, k);
    }

    const mss = blk: {
        const s = tcp.first("tcp.options.mss_val") orelse break :blk @as(?u16, null);
        break :blk @as(?u16, std.fmt.parseInt(u16, s, 10) catch null);
    };
    const wscale = blk: {
        const s = tcp.first("tcp.options.wscale.shift") orelse break :blk @as(?u8, null);
        break :blk @as(?u8, std.fmt.parseInt(u8, s, 10) catch null);
    };

    state.client = .{
        .pkt_num = pkt.num,
        .window_size = window_size.?,
        .options = try opts.toOwnedSlice(gpa),
        .mss = mss,
        .window_scale = wscale,
    };
}

fn isInitialSyn(flags: u16) bool {
    return (flags & 0x02) != 0 and (flags & 0x10) == 0;
}

fn parseIntFlexible(comptime T: type, s: []const u8) !T {
    if (std.mem.startsWith(u8, s, "0x") or std.mem.startsWith(u8, s, "0X")) {
        return std.fmt.parseInt(T, s[2..], 16);
    }
    return std.fmt.parseInt(T, s, 10);
}

/// Emits `ja4t: <ws>_<opt-dash-joined>_<mss-or-0>_<wscale-or-0>` (and
/// `pkt_ja4t: <n>` when `with_packet_numbers`).
pub fn emit(state: State, w: *std.Io.Writer, with_packet_numbers: bool) !void {
    const c = state.client orelse return;
    if (with_packet_numbers) try w.print("  pkt_ja4t: {d}\n", .{c.pkt_num});
    try w.print("  ja4t: {d}_", .{c.window_size});
    for (c.options, 0..) |k, i| {
        if (i != 0) try w.print("-", .{});
        try w.print("{d}", .{k});
    }
    try w.print("_{d}_{d}\n", .{ c.mss orelse 0, c.window_scale orelse 0 });
}

test "isInitialSyn" {
    try std.testing.expect(isInitialSyn(0x0002));
    try std.testing.expect(!isInitialSyn(0x0012)); // SYN+ACK
    try std.testing.expect(!isInitialSyn(0x0010)); // bare ACK
}
