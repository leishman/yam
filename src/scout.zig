// Scout.zig - Peer discovery module
// Named after military scouts who gather intelligence on terrain and enemy positions

const std = @import("std");
const yam = @import("root.zig");
const message_utils = @import("message_utils.zig");

/// DNS seeds for Bitcoin mainnet peer discovery
const dns_seeds = [_][]const u8{
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "seed.bitcoinstats.com",
    "seed.bitcoin.jonasschnelli.ch",
    "seed.btc.petertodd.net",
    "seed.bitcoin.sprovoost.nl",
    "dnsseed.emzy.de",
    "seed.bitcoin.wiz.biz",
};

/// Hardcoded fallback peers (in case DNS fails)
const fallback_peers = [_]struct { ip: []const u8, port: u16 }{
    .{ .ip = "172.7.56.107", .port = 8333 },
    .{ .ip = "162.220.94.10", .port = 8333 },
    .{ .ip = "49.13.4.145", .port = 8333 },
};

/// Discover peers via DNS seeds
pub fn discoverPeers(allocator: std.mem.Allocator) !std.ArrayList(yam.PeerInfo) {
    var peers = std.ArrayList(yam.PeerInfo).empty;
    errdefer peers.deinit(allocator);

    // Try DNS seeds
    for (dns_seeds) |seed| {
        const addresses = std.net.getAddressList(allocator, seed, 8333) catch |err| {
            std.debug.print("DNS lookup failed for {s}: {}\n", .{ seed, err });
            continue;
        };
        defer addresses.deinit();

        for (addresses.addrs) |addr| {
            // Only add IPv4 for now
            if (addr.any.family == std.posix.AF.INET) {
                try peers.append(allocator, .{
                    .address = addr,
                    .services = 0,
                    .source = .dns_seed,
                });
            }
        }
    }

    // If DNS failed completely, use fallback peers
    if (peers.items.len == 0) {
        std.debug.print("DNS discovery failed, using fallback peers\n", .{});
        for (fallback_peers) |fallback| {
            const addr = std.net.Address.parseIp4(fallback.ip, fallback.port) catch continue;
            try peers.append(allocator, .{
                .address = addr,
                .services = 0,
                .source = .hardcoded_fallback,
            });
        }
    }

    std.debug.print("Discovered {d} peers\n", .{peers.items.len});
    return peers;
}

/// Discover additional peers by connecting to known peers and requesting addresses via getaddr
pub fn discoverPeersViaGetaddr(
    allocator: std.mem.Allocator,
    initial_peers: []const yam.PeerInfo,
    max_peers_to_query: usize,
) !std.ArrayList(yam.PeerInfo) {
    var all_peers = std.ArrayList(yam.PeerInfo).empty;
    errdefer all_peers.deinit(allocator);

    // Copy initial peers
    for (initial_peers) |peer| {
        try all_peers.append(allocator, peer);
    }

    // Track addresses we've seen to avoid duplicates
    var seen = std.AutoHashMap(u32, void).init(allocator);
    defer seen.deinit();

    for (initial_peers) |peer| {
        if (peer.address.any.family == std.posix.AF.INET) {
            const ip_int = @as(*const u32, @ptrCast(&peer.address.in.sa.addr)).*;
            try seen.put(ip_int, {});
        }
    }

    // Query a subset of peers for addresses
    const peers_to_query = @min(max_peers_to_query, initial_peers.len);
    var queried: usize = 0;

    for (initial_peers) |peer| {
        if (queried >= peers_to_query) break;

        const new_addrs = queryPeerForAddresses(allocator, peer) catch |err| {
            std.debug.print("getaddr failed for peer: {}\n", .{err});
            continue;
        };
        defer allocator.free(new_addrs);

        for (new_addrs) |new_peer| {
            if (new_peer.address.any.family == std.posix.AF.INET) {
                const ip_int = @as(*const u32, @ptrCast(&new_peer.address.in.sa.addr)).*;
                if (!seen.contains(ip_int)) {
                    try seen.put(ip_int, {});
                    try all_peers.append(allocator, new_peer);
                }
            }
        }

        queried += 1;
    }

    std.debug.print("Expanded peer list to {d} peers\n", .{all_peers.items.len});
    return all_peers;
}

/// Query a single peer for addresses via getaddr message
fn queryPeerForAddresses(allocator: std.mem.Allocator, peer: yam.PeerInfo) ![]yam.PeerInfo {
    var stream = try std.net.tcpConnectToAddress(peer.address);
    defer stream.close();

    // Perform handshake
    try performHandshake(stream, allocator);

    // Send getaddr
    const checksum = yam.calculateChecksum(&.{});
    const header = yam.MessageHeader.new("getaddr", 0, checksum);
    try stream.writeAll(std.mem.asBytes(&header));

    // Wait for addr response
    var peers = std.ArrayList(yam.PeerInfo).empty;
    errdefer peers.deinit(allocator);

    const timeout_ns: u64 = 5_000_000_000; // 5 seconds
    const start = std.time.nanoTimestamp();

    while (true) {
        const elapsed: u64 = @intCast(std.time.nanoTimestamp() - start);
        if (elapsed > timeout_ns) break;

        // Use same strict validation as courier (4MB limit + checksum verification)
        const message = message_utils.readMessage(stream, allocator, .{
            .max_payload_size = message_utils.MAX_PAYLOAD_SIZE,
            .verify_checksum = true,
        }) catch break;
        defer if (message.payload.len > 0) allocator.free(message.payload);

        const cmd = std.mem.sliceTo(&message.header.command, 0);

        if (std.mem.eql(u8, cmd, "addr")) {
            var fbs = std.io.fixedBufferStream(message.payload);
            const addr_msg = yam.AddrMessage.deserialize(fbs.reader(), allocator) catch break;
            defer addr_msg.deinit(allocator);

            for (addr_msg.addresses) |net_addr| {
                if (net_addr.toPeerInfo(.addr_message)) |peer_info| {
                    try peers.append(allocator, peer_info);
                }
            }
            break;
        }
    }

    return try peers.toOwnedSlice(allocator);
}

/// Perform Bitcoin P2P handshake
fn performHandshake(stream: std.net.Stream, allocator: std.mem.Allocator) !void {
    var nonce: u64 = undefined;
    try std.posix.getrandom(std.mem.asBytes(&nonce));

    const version_payload = yam.VersionPayload{
        .timestamp = std.time.timestamp(),
        .nonce = nonce,
        .relay = false,
    };

    var payload_buffer = std.ArrayList(u8).empty;
    defer payload_buffer.deinit(allocator);
    try version_payload.serialize(payload_buffer.writer(allocator));

    try sendMessage(stream, "version", payload_buffer.items);

    var received_version = false;
    var received_verack = false;
    const timeout_ms: i64 = 30_000;
    const start = std.time.milliTimestamp();

    while (!received_version or !received_verack) {
        if (std.time.milliTimestamp() - start > timeout_ms) {
            return error.HandshakeTimeout;
        }

        // Use same strict validation as courier (4MB limit + checksum verification)
        const message = try message_utils.readMessage(stream, allocator, .{
            .max_payload_size = message_utils.MAX_PAYLOAD_SIZE,
            .verify_checksum = true,
        });
        defer if (message.payload.len > 0) allocator.free(message.payload);

        const cmd = std.mem.sliceTo(&message.header.command, 0);

        if (std.mem.eql(u8, cmd, "version")) {
            received_version = true;

            var fbs = std.io.fixedBufferStream(message.payload);
            const peer_version = try yam.VersionPayload.deserialize(fbs.reader(), allocator);
            defer allocator.free(peer_version.user_agent);

            try sendMessage(stream, "verack", &.{});
        } else if (std.mem.eql(u8, cmd, "verack")) {
            received_verack = true;
        }
    }
}

fn sendMessage(stream: std.net.Stream, command: []const u8, payload: []const u8) !void {
    const checksum = yam.calculateChecksum(payload);
    const header = yam.MessageHeader.new(command, @intCast(payload.len), checksum);

    try stream.writeAll(std.mem.asBytes(&header));
    if (payload.len > 0) {
        try stream.writeAll(payload);
    }
}

/// Select random peers from a list
pub fn selectRandomPeers(
    allocator: std.mem.Allocator,
    peers: []const yam.PeerInfo,
    count: u32,
) ![]yam.PeerInfo {
    if (peers.len == 0) return error.NoPeersAvailable;

    const actual_count = @min(count, peers.len);
    var selected = try allocator.alloc(yam.PeerInfo, actual_count);
    errdefer allocator.free(selected);

    // Fisher-Yates shuffle on indices
    var indices = try allocator.alloc(usize, peers.len);
    defer allocator.free(indices);

    for (indices, 0..) |*idx, i| {
        idx.* = i;
    }

    var rng_seed: u64 = undefined;
    try std.posix.getrandom(std.mem.asBytes(&rng_seed));
    var rng = std.Random.DefaultPrng.init(rng_seed);

    // Partial shuffle - only need first actual_count elements
    for (0..actual_count) |i| {
        const j = rng.random().intRangeAtMost(usize, i, peers.len - 1);
        const tmp = indices[i];
        indices[i] = indices[j];
        indices[j] = tmp;
    }

    for (0..actual_count) |i| {
        selected[i] = peers[indices[i]];
    }

    return selected;
}

/// Get human-readable name for peer source
pub fn sourceName(source: yam.PeerSource) []const u8 {
    return switch (source) {
        .dns_seed => "(DNS)",
        .addr_message => "(addr)",
        .cli_manual => "(manual)",
        .hardcoded_fallback => "(fallback)",
    };
}
