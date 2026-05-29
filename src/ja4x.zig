//! JA4X — X.509 cert fingerprint. Minimal ASN.1/DER walker — just enough
//! to enumerate the issuer/subject RDN attribute OIDs and the certificate
//! extension OIDs.
//!
//! Algorithm (per `rust/ja4x/src/lib.rs`):
//!   issuer_rdns   = hex(oid_bytes) comma-joined for all issuer attributes
//!   subject_rdns  = same for subject
//!   extensions    = same for cert extensions
//!   ja4x          = hash12(issuer_rdns) "_" hash12(subject_rdns) "_" hash12(extensions)
//!   ja4x_r        = issuer_rdns "_" subject_rdns "_" extensions   (with -r)
//!
//! Cert structure (RFC 5280):
//!   Certificate ::= SEQUENCE {
//!     tbsCertificate       TBSCertificate,        <- we want this
//!     signatureAlgorithm   AlgorithmIdentifier,
//!     signatureValue       BIT STRING
//!   }
//!   TBSCertificate ::= SEQUENCE {
//!     version          [0] EXPLICIT Version DEFAULT v1,  -- optional context tag
//!     serialNumber     INTEGER,
//!     signature        AlgorithmIdentifier,
//!     issuer           Name,                              <- want
//!     validity         Validity,
//!     subject          Name,                              <- want
//!     subjectPublicKey SubjectPublicKeyInfo,
//!     issuerUniqueID   [1] IMPLICIT UniqueIdentifier OPTIONAL,
//!     subjectUniqueID  [2] IMPLICIT UniqueIdentifier OPTIONAL,
//!     extensions       [3] EXPLICIT Extensions OPTIONAL   <- want
//!   }
//!
//! Name = SEQUENCE OF RDN; RDN = SET OF AttributeTypeAndValue;
//! AttributeTypeAndValue = SEQUENCE { type OID, value ANY }
//!
//! Extensions = SEQUENCE OF Extension; Extension = SEQUENCE { OID, ... }

const std = @import("std");
const hash = @import("hash.zig");
const yaml = @import("yaml.zig");

pub const OidKv = struct {
    /// e.g. "issuerCountryName". Owned.
    key: []u8,
    /// e.g. "US". Owned.
    value: []u8,
};

pub const Record = struct {
    pkt_num: u32,
    issuer_rdns: []u8, // hex CSV of OID bytes — owned
    subject_rdns: []u8,
    extension_oids: []u8,
    /// Pretty issuer + subject KV pairs (issuerCountryName: "US", etc.)
    kvs: []OidKv,

    pub fn deinit(self: *Record, gpa: std.mem.Allocator) void {
        gpa.free(self.issuer_rdns);
        gpa.free(self.subject_rdns);
        gpa.free(self.extension_oids);
        for (self.kvs) |kv| {
            gpa.free(kv.key);
            gpa.free(kv.value);
        }
        gpa.free(self.kvs);
    }
};

/// Group of records all extracted from the same packet.
pub const RecordGroup = struct {
    pkt_num: u32,
    records: []Record,

    pub fn deinit(self: *RecordGroup, gpa: std.mem.Allocator) void {
        for (self.records) |*r| r.deinit(gpa);
        gpa.free(self.records);
    }
};

pub const State = struct {
    groups: std.ArrayList(RecordGroup) = .empty,

    pub fn deinit(self: *State, gpa: std.mem.Allocator) void {
        for (self.groups.items) |*g| g.deinit(gpa);
        self.groups.deinit(gpa);
    }
};

/// Parse one packet's certificates (called when tls.handshake.type == "11").
/// `cert_hex` is one of the colon-separated hex strings from
/// `tls.handshake.certificate` (tshark formats them like `"30:82:..."`).
pub fn buildRecord(gpa: std.mem.Allocator, pkt_num: u32, cert_hex: []const u8) !?Record {
    // Decode colon-hex → bytes.
    var der: std.ArrayList(u8) = .empty;
    defer der.deinit(gpa);
    var i: usize = 0;
    while (i + 1 < cert_hex.len) {
        const hi = hexNibble(cert_hex[i]) orelse return null;
        const lo = hexNibble(cert_hex[i + 1]) orelse return null;
        try der.append(gpa, (hi << 4) | lo);
        i += 2;
        if (i < cert_hex.len and cert_hex[i] == ':') i += 1;
    }

    return try parseDer(gpa, pkt_num, der.items);
}

fn hexNibble(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

const Walker = struct {
    data: []const u8,
    pos: usize,

    fn rem(self: Walker) []const u8 {
        return self.data[self.pos..];
    }

    fn need(self: *Walker, n: usize) ![]const u8 {
        if (self.pos + n > self.data.len) return error.DerEof;
        const r = self.data[self.pos .. self.pos + n];
        self.pos += n;
        return r;
    }

    /// Reads (tag, len, content). Updates `pos` past the content.
    fn nextTlv(self: *Walker) !struct { tag: u8, content: []const u8 } {
        const t = (try self.need(1))[0];
        const l = try self.readLen();
        const c = try self.need(l);
        return .{ .tag = t, .content = c };
    }

    fn readLen(self: *Walker) !usize {
        const b0 = (try self.need(1))[0];
        if (b0 & 0x80 == 0) return b0;
        const nbytes = b0 & 0x7f;
        if (nbytes == 0 or nbytes > 4) return error.DerLen;
        var l: usize = 0;
        const bytes = try self.need(nbytes);
        for (bytes) |b| l = (l << 8) | b;
        return l;
    }
};

fn parseDer(gpa: std.mem.Allocator, pkt_num: u32, der: []const u8) !?Record {
    var top: Walker = .{ .data = der, .pos = 0 };
    const outer = try top.nextTlv();
    if (outer.tag != 0x30) return null;

    var tbs_w: Walker = .{ .data = outer.content, .pos = 0 };
    const tbs = try tbs_w.nextTlv();
    if (tbs.tag != 0x30) return null;

    var w: Walker = .{ .data = tbs.content, .pos = 0 };

    // Optional version: [0] EXPLICIT
    if (w.rem().len > 0 and w.rem()[0] == 0xa0) {
        _ = try w.nextTlv();
    }
    // serialNumber INTEGER
    _ = try w.nextTlv();
    // signature AlgorithmIdentifier
    _ = try w.nextTlv();
    // issuer Name
    const issuer_tlv = try w.nextTlv();
    if (issuer_tlv.tag != 0x30) return null;
    // validity
    _ = try w.nextTlv();
    // subject Name
    const subject_tlv = try w.nextTlv();
    if (subject_tlv.tag != 0x30) return null;
    // subjectPublicKey
    _ = try w.nextTlv();

    // Walk remaining: extensions live in [3] EXPLICIT.
    var ext_bytes: ?[]const u8 = null;
    while (w.rem().len > 0) {
        const tlv = try w.nextTlv();
        if (tlv.tag == 0xa3) {
            // EXPLICIT [3] wraps a SEQUENCE OF Extension.
            var ew: Walker = .{ .data = tlv.content, .pos = 0 };
            const seq = try ew.nextTlv();
            if (seq.tag == 0x30) ext_bytes = seq.content;
        }
    }

    var issuer_oids: std.ArrayList(u8) = .empty;
    defer issuer_oids.deinit(gpa);
    var subject_oids: std.ArrayList(u8) = .empty;
    defer subject_oids.deinit(gpa);
    var ext_oids: std.ArrayList(u8) = .empty;
    defer ext_oids.deinit(gpa);

    var kvs: std.ArrayList(OidKv) = .empty;
    errdefer {
        for (kvs.items) |kv| {
            gpa.free(kv.key);
            gpa.free(kv.value);
        }
        kvs.deinit(gpa);
    }

    try walkName(gpa, issuer_tlv.content, &issuer_oids, &kvs, "issuer");
    try walkName(gpa, subject_tlv.content, &subject_oids, &kvs, "subject");

    if (ext_bytes) |eb| try walkExtensions(gpa, eb, &ext_oids);

    return .{
        .pkt_num = pkt_num,
        .issuer_rdns = try issuer_oids.toOwnedSlice(gpa),
        .subject_rdns = try subject_oids.toOwnedSlice(gpa),
        .extension_oids = try ext_oids.toOwnedSlice(gpa),
        .kvs = try kvs.toOwnedSlice(gpa),
    };
}

/// Walks a `Name` SEQUENCE OF RDN, appending each AttributeType OID (hex)
/// to `oids_out` (comma-joined) and each (key, value) to `kvs`.
fn walkName(
    gpa: std.mem.Allocator,
    name_bytes: []const u8,
    oids_out: *std.ArrayList(u8),
    kvs: *std.ArrayList(OidKv),
    prefix: []const u8,
) !void {
    var w: Walker = .{ .data = name_bytes, .pos = 0 };
    var first = true;
    while (w.rem().len > 0) {
        const rdn = try w.nextTlv();
        if (rdn.tag != 0x31) continue; // SET
        var rdn_w: Walker = .{ .data = rdn.content, .pos = 0 };
        while (rdn_w.rem().len > 0) {
            const atv = try rdn_w.nextTlv();
            if (atv.tag != 0x30) continue;
            var atv_w: Walker = .{ .data = atv.content, .pos = 0 };
            const oid_tlv = try atv_w.nextTlv();
            if (oid_tlv.tag != 0x06) continue;
            // hex-encode OID bytes.
            if (!first) try oids_out.append(gpa, ',');
            first = false;
            for (oid_tlv.content) |b| {
                var hb: [2]u8 = undefined;
                _ = std.fmt.bufPrint(&hb, "{x:0>2}", .{b}) catch unreachable;
                try oids_out.appendSlice(gpa, &hb);
            }
            // Pull short name + value.
            const val_tlv = try atv_w.nextTlv();
            if (oidShortName(oid_tlv.content)) |sn| {
                if (asString(val_tlv.tag, val_tlv.content)) |s| {
                    var key: std.ArrayList(u8) = .empty;
                    errdefer key.deinit(gpa);
                    try key.appendSlice(gpa, prefix);
                    // Capitalize first char of sn.
                    if (sn.len > 0) {
                        const c0 = sn[0];
                        const C = if (c0 >= 'a' and c0 <= 'z') c0 - 32 else c0;
                        try key.append(gpa, C);
                        try key.appendSlice(gpa, sn[1..]);
                    }
                    const value = try gpa.dupe(u8, s);
                    try kvs.append(gpa, .{
                        .key = try key.toOwnedSlice(gpa),
                        .value = value,
                    });
                }
            }
        }
    }
}

fn walkExtensions(gpa: std.mem.Allocator, ext_bytes: []const u8, oids_out: *std.ArrayList(u8)) !void {
    var w: Walker = .{ .data = ext_bytes, .pos = 0 };
    var first = true;
    while (w.rem().len > 0) {
        const ext = try w.nextTlv();
        if (ext.tag != 0x30) continue;
        var ew: Walker = .{ .data = ext.content, .pos = 0 };
        const oid_tlv = try ew.nextTlv();
        if (oid_tlv.tag != 0x06) continue;
        if (!first) try oids_out.append(gpa, ',');
        first = false;
        for (oid_tlv.content) |b| {
            var hb: [2]u8 = undefined;
            _ = std.fmt.bufPrint(&hb, "{x:0>2}", .{b}) catch unreachable;
            try oids_out.appendSlice(gpa, &hb);
        }
    }
}

/// Returns the human-readable short name for known X.509 RDN OIDs. Returns
/// null when we don't recognise the OID — those RDNs are still hashed into
/// the JA4X digest (via their hex bytes) but won't get pretty kv pairs.
fn oidShortName(oid_bytes: []const u8) ?[]const u8 {
    // OID 2.5.4.x: bytes 55 04 xx
    if (oid_bytes.len == 3 and oid_bytes[0] == 0x55 and oid_bytes[1] == 0x04) {
        return switch (oid_bytes[2]) {
            3 => "commonName",
            5 => "serialNumber",
            6 => "countryName",
            7 => "localityName",
            8 => "stateOrProvinceName",
            9 => "streetAddress",
            10 => "organizationName",
            11 => "organizationalUnit",
            12 => "title",
            13 => "description",
            15 => "businessCategory",
            17 => "postalCode",
            else => null,
        };
    }
    // NOTE: emailAddress (1.2.840.113549.1.9.1) is intentionally NOT in
    // this map — x509-parser's default `with_x509()` registry omits it, so
    // the upstream Rust impl drops it from JA4X output.
    // 0.9.2342.19200300.100.1.25 — domainComponent: 09 92 26 89 93 f2 2c 64 01 19
    if (std.mem.eql(u8, oid_bytes, &.{ 0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19 })) return "domainComponent";
    // 1.3.6.1.4.1.311.60.2.1.3 — jurisdictionCountryName (MS).
    if (std.mem.eql(u8, oid_bytes, &.{ 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3c, 0x02, 0x01, 0x03 })) return "msJurisdictionCountry";
    // 1.3.6.1.4.1.311.60.2.1.2 — jurisdictionStateOrProvince (MS).
    if (std.mem.eql(u8, oid_bytes, &.{ 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3c, 0x02, 0x01, 0x02 })) return "msJurisdictionStateOrProvince";
    // 1.3.6.1.4.1.311.60.2.1.1 — jurisdictionLocalityName (MS).
    if (std.mem.eql(u8, oid_bytes, &.{ 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3c, 0x02, 0x01, 0x01 })) return "msJurisdictionLocality";
    return null;
}

fn asString(tag: u8, content: []const u8) ?[]const u8 {
    // UTF8String (0x0c), PrintableString (0x13), TeletexString (0x14),
    // IA5String (0x16), BMPString (0x1e). For all of these we just take the
    // raw bytes; BMPString is UTF-16BE in spec but Wireshark snapshots
    // don't seem to contain any of them in our corpus.
    return switch (tag) {
        0x0c, 0x13, 0x14, 0x16, 0x1e => content,
        else => null,
    };
}

/// Emits the `tls_certs:` block for one stream — one entry per packet that
/// carried certificates.
pub fn emit(
    state: State,
    w: *std.Io.Writer,
    with_packet_numbers: bool,
    with_raw: bool,
) !void {
    if (state.groups.items.len == 0) return;
    try w.print("  tls_certs:\n", .{});
    for (state.groups.items) |grp| {
        if (with_packet_numbers) try w.print("  - pkt_x509: {d}\n    x509:\n", .{grp.pkt_num}) else try w.print("  - x509:\n", .{});
        for (grp.records, 0..) |rec, i| {
            var h_iss: [12]u8 = undefined;
            hash.hash12(rec.issuer_rdns, &h_iss);
            var h_sub: [12]u8 = undefined;
            hash.hash12(rec.subject_rdns, &h_sub);
            var h_ext: [12]u8 = undefined;
            hash.hash12(rec.extension_oids, &h_ext);
            const prefix = if (i == 0) "    -" else "    -";
            _ = prefix;
            try w.print("    - ja4x: {s}_{s}_{s}\n", .{ &h_iss, &h_sub, &h_ext });
            if (with_raw) {
                try w.print("      ja4x_r: {s}_{s}_{s}\n", .{ rec.issuer_rdns, rec.subject_rdns, rec.extension_oids });
            }
            for (rec.kvs) |kv| {
                try w.print("      {s}: ", .{kv.key});
                try yaml.writeScalar(w, kv.value);
                try w.print("\n", .{});
            }
        }
    }
}
