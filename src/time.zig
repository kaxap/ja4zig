//! JA4L-C / JA4L-S — light-distance latency fingerprints.

const std = @import("std");
const pcap = @import("pcap.zig");

pub const Transport = enum { tcp, udp };

pub const State = struct {
    transport: Transport,
    // TCP states
    t_syn: ?i64 = null,
    t_syn_ack: ?i64 = null,
    t_ack: ?i64 = null,
    client_ttl: ?u8 = null,
    server_ttl: ?u8 = null,
    // QUIC states (port-443 UDP only)
    t_client_initial: ?i64 = null,
    t_server_initial: ?i64 = null,
    t_server_hs: ?i64 = null,
    t_client_hs: ?i64 = null,

    pub fn init(transport: Transport) State {
        return .{ .transport = transport };
    }
};

pub fn update(state: *State, pkt: pcap.Packet) !void {
    switch (state.transport) {
        .tcp => try updateTcp(state, pkt),
        .udp => try updateUdp(state, pkt),
    }
}

fn updateTcp(state: *State, pkt: pcap.Packet) !void {
    const tcp = pkt.findProto("tcp") orelse return;
    const syn = isTrueish(tcp.first("tcp.flags.syn"));
    const ack = isTrueish(tcp.first("tcp.flags.ack"));

    if (syn and !ack) {
        if (state.t_syn != null) return;
        state.t_syn = pkt.timestamp_us;
        state.client_ttl = readTtl(pkt);
    } else if (syn and ack) {
        if (state.t_syn == null or state.t_syn_ack != null) return;
        state.t_syn_ack = pkt.timestamp_us;
        state.server_ttl = readTtl(pkt);
    } else if (!syn and ack) {
        if (state.t_syn_ack == null or state.t_ack != null) return;
        state.t_ack = pkt.timestamp_us;
    }
}

fn updateUdp(state: *State, pkt: pcap.Packet) !void {
    if (!pkt.hasProto("quic")) return;
    const udp = pkt.findProto("udp") orelse return;
    const dstport = udp.first("udp.dstport") orelse "";
    const srcport = udp.first("udp.srcport") orelse "";
    const is_client = std.mem.eql(u8, dstport, "443");
    const is_server = std.mem.eql(u8, srcport, "443");
    if (!is_client and !is_server) return;

    const quic = pkt.findProto("quic") orelse return;
    const ptype = quic.first("quic.long.packet_type") orelse return;
    const t = pkt.timestamp_us;

    if (is_client and std.mem.eql(u8, ptype, "0")) {
        if (state.t_client_initial == null) {
            state.t_client_initial = t;
            state.client_ttl = readTtl(pkt);
        }
    } else if (is_server and std.mem.eql(u8, ptype, "0")) {
        if (state.t_client_initial != null and state.t_server_initial == null) {
            state.t_server_initial = t;
            state.server_ttl = readTtl(pkt);
        }
    } else if (is_server and std.mem.eql(u8, ptype, "2")) {
        if (state.t_server_initial != null and state.t_client_hs == null) {
            state.t_server_hs = t; // overwrite until client handshake fires
        }
    } else if (is_client and std.mem.eql(u8, ptype, "2")) {
        if (state.t_server_hs != null and state.t_client_hs == null) {
            state.t_client_hs = t;
        }
    }
}

fn readTtl(pkt: pcap.Packet) ?u8 {
    if (pkt.findProto("ip")) |ip| {
        if (ip.first("ip.ttl")) |s| {
            return std.fmt.parseInt(u8, s, 10) catch null;
        }
    }
    if (pkt.findProto("ipv6")) |ip6| {
        if (ip6.first("ipv6.hlim")) |s| {
            return std.fmt.parseInt(u8, s, 10) catch null;
        }
    }
    return null;
}

fn isTrueish(v: ?[]const u8) bool {
    const s = v orelse return false;
    return std.mem.eql(u8, s, "1") or std.mem.eql(u8, s, "true") or std.mem.eql(u8, s, "True");
}

pub fn emit(state: State, w: *std.Io.Writer) !void {
    var ja4l_c_us: ?i64 = null;
    var ja4l_s_us: ?i64 = null;
    switch (state.transport) {
        .tcp => {
            if (state.t_syn != null and state.t_syn_ack != null and state.t_ack != null) {
                ja4l_s_us = @divTrunc(state.t_syn_ack.? - state.t_syn.?, 2);
                ja4l_c_us = @divTrunc(state.t_ack.? - state.t_syn_ack.?, 2);
            }
        },
        .udp => {
            if (state.t_client_initial != null and state.t_server_initial != null and
                state.t_server_hs != null and state.t_client_hs != null)
            {
                ja4l_s_us = @divTrunc(state.t_server_initial.? - state.t_client_initial.?, 2);
                ja4l_c_us = @divTrunc(state.t_client_hs.? - state.t_server_hs.?, 2);
            }
        },
    }
    if (ja4l_c_us == null or ja4l_s_us == null) return;
    if (state.client_ttl) |t| try w.print("  ja4l_c: {d}_{d}\n", .{ ja4l_c_us.?, t });
    if (state.server_ttl) |t| try w.print("  ja4l_s: {d}_{d}\n", .{ ja4l_s_us.?, t });
}
