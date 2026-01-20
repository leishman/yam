// Courier.zig - Individual peer connection handler
// Named after the mounted messengers of the Yam postal system

const std = @import("std");
const yam = @import("root.zig");
const message_utils = @import("message_utils.zig");

/// Maximum payload size for peer messages (4 MB)
/// This limit prevents memory exhaustion from malicious or misbehaving peers
const MAX_PAYLOAD_SIZE: u32 = 4_000_000;

/// Courier manages a connection to a single Bitcoin peer
pub const Courier = struct {
    peer: yam.PeerInfo,
    allocator: std.mem.Allocator,
    stream: ?std.net.Stream,
    connected: bool,

    pub fn init(peer: yam.PeerInfo, allocator: std.mem.Allocator) Courier {
        return .{
            .peer = peer,
            .allocator = allocator,
            .stream = null,
            .connected = false,
        };
    }

    pub fn deinit(self: *Courier) void {
        if (self.stream) |stream| {
            stream.close();
        }
        self.stream = null;
        self.connected = false;
    }

    /// Connect to peer and perform handshake
    pub fn connect(self: *Courier) !void {
        if (self.connected) return;

        // Connect with timeout
        self.stream = try std.net.tcpConnectToAddress(self.peer.address);
        errdefer {
            if (self.stream) |stream| stream.close();
            self.stream = null;
        }

        // Perform handshake
        try self.performHandshake();
        self.connected = true;
    }

    /// Perform Bitcoin P2P version handshake
    fn performHandshake(self: *Courier) !void {
        _ = self.stream orelse return error.NotConnected;

        var nonce: u64 = undefined;
        try std.posix.getrandom(std.mem.asBytes(&nonce));

        const version_payload = yam.VersionPayload{
            .timestamp = std.time.timestamp(),
            .nonce = nonce,
            .relay = true,
        };

        var payload_buffer = std.ArrayList(u8).empty;
        defer payload_buffer.deinit(self.allocator);
        try version_payload.serialize(payload_buffer.writer(self.allocator));

        try self.sendMessage("version", payload_buffer.items);

        var received_version = false;
        var received_verack = false;
        const timeout_ms: i64 = 30_000;
        const start = std.time.milliTimestamp();

        while (!received_version or !received_verack) {
            if (std.time.milliTimestamp() - start > timeout_ms) {
                return error.HandshakeTimeout;
            }

            // Use shared message reading utility with 4 MB limit and checksum verification
            // (courier.zig enforces stricter limits for individual peer connections)
            const message = try self.readMessageChecked();
            defer if (message.payload.len > 0) self.allocator.free(message.payload);

            const cmd = std.mem.sliceTo(&message.header.command, 0);

            if (std.mem.eql(u8, cmd, "version")) {
                received_version = true;

                var fbs = std.io.fixedBufferStream(message.payload);
                const peer_version = try yam.VersionPayload.deserialize(fbs.reader(), self.allocator);
                defer self.allocator.free(peer_version.user_agent);

                try self.sendMessage("verack", &.{});
            } else if (std.mem.eql(u8, cmd, "verack")) {
                received_verack = true;
            }
        }
    }

    /// Send a raw transaction to the peer
    pub fn sendTx(self: *Courier, tx_bytes: []const u8) !void {
        if (!self.connected) return error.NotConnected;

        // First, send an inv message announcing the transaction
        var inv_payload = std.ArrayList(u8).empty;
        defer inv_payload.deinit(self.allocator);

        const writer = inv_payload.writer(self.allocator);

        // Calculate txid (double SHA256)
        var h1: [32]u8 = undefined;
        var h2: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(tx_bytes, &h1, .{});
        std.crypto.hash.sha2.Sha256.hash(&h1, &h2, .{});

        // inv message: count (1) + type (MSG_TX=1) + hash (32 bytes)
        try writer.writeByte(1); // count = 1
        try writer.writeInt(u32, 1, .little); // MSG_TX
        try writer.writeAll(&h2); // txid (not reversed - wire format)

        try self.sendMessage("inv", inv_payload.items);

        // Wait for getdata request (peer wants the full transaction)
        const got_getdata = try self.waitForGetdata(&h2, 5000);

        if (got_getdata) {
            // Send the full transaction
            try self.sendMessage("tx", tx_bytes);
        }
    }

    /// Wait for a getdata message requesting our transaction
    fn waitForGetdata(self: *Courier, txid: *const [32]u8, timeout_ms: u64) !bool {
        const start = std.time.milliTimestamp();

        while (true) {
            const elapsed: u64 = @intCast(std.time.milliTimestamp() - start);
            if (elapsed > timeout_ms) return false;

            // Use shared message reading utility with 4 MB limit and checksum verification
            const message = self.readMessageChecked() catch |err| {
                if (err == error.WouldBlock) continue;
                return false;
            };
            defer if (message.payload.len > 0) self.allocator.free(message.payload);

            const cmd = std.mem.sliceTo(&message.header.command, 0);

            if (std.mem.eql(u8, cmd, "getdata")) {
                // Check if it's requesting our txid
                if (message.payload.len >= 37) {
                    const requested_hash = message.payload[5..37];
                    if (std.mem.eql(u8, requested_hash, txid)) {
                        return true;
                    }
                }
            } else if (std.mem.eql(u8, cmd, "ping")) {
                // Respond to pings to keep connection alive
                try self.sendMessage("pong", message.payload);
            }
        }
    }

    fn sendMessage(self: *Courier, command: []const u8, payload: []const u8) !void {
        const stream = self.stream orelse return error.NotConnected;

        const checksum = yam.calculateChecksum(payload);
        const header = yam.MessageHeader.new(command, @intCast(payload.len), checksum);

        try stream.writeAll(std.mem.asBytes(&header));
        if (payload.len > 0) {
            try stream.writeAll(payload);
        }
    }

    /// Helper method to read a message with courier's strict validation settings
    /// (4 MB payload limit + checksum verification)
    fn readMessageChecked(self: *Courier) !message_utils.Message {
        const stream = self.stream orelse return error.NotConnected;
        return message_utils.readMessage(stream, self.allocator, .{
            .max_payload_size = MAX_PAYLOAD_SIZE,
            .verify_checksum = true,
        });
    }
};
