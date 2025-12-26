// Root.zig - Bitcoin P2P protocol implementation
// https://en.bitcoin.it/wiki/Protocol_documentation was used as the reference for this implementation.

const std = @import("std");

pub const MessageHeader = extern struct {
    magic: u32 = 0xD9B4BEF9,
    command: [12]u8,
    length: u32,
    checksum: u32,

    pub fn new(cmd: []const u8, payload_len: u32, payload_checksum: u32) MessageHeader {
        var header = MessageHeader{
            .command = [_]u8{0} ** 12,
            .length = payload_len,
            .checksum = payload_checksum,
        };
        @memcpy(header.command[0..cmd.len], cmd);
        return header;
    }
};

// Bitcoin service flags
pub const ServiceFlags = struct {
    pub const NODE_NETWORK: u64 = 0x01; // Full node with full blockchain
    pub const NODE_GETUTXO: u64 = 0x02; // Supports getutxo messages
    pub const NODE_BLOOM: u64 = 0x04; // Supports Bloom filters (SPV clients)
    pub const NODE_WITNESS: u64 = 0x08; // Supports SegWit
    pub const NODE_XTHIN: u64 = 0x10; // Supports Xtreme Thinblocks
    pub const NODE_NETWORK_LIMITED: u64 = 0x1000; // Pruned node (last 288 blocks)
    pub const NODE_COMPACT_FILTERS: u64 = 0x2000; // Supports BIP157/158 compact block filters

    pub fn decode(flags: u64) struct {
        network: bool,
        getutxo: bool,
        bloom: bool,
        witness: bool,
        network_limited: bool,
        compact_filters: bool,
    } {
        return .{
            .network = (flags & NODE_NETWORK) != 0,
            .getutxo = (flags & NODE_GETUTXO) != 0,
            .bloom = (flags & NODE_BLOOM) != 0,
            .witness = (flags & NODE_WITNESS) != 0,
            .network_limited = (flags & NODE_NETWORK_LIMITED) != 0,
            .compact_filters = (flags & NODE_COMPACT_FILTERS) != 0,
        };
    }
};

// Version payload
pub const VersionPayload = struct {
    version: i32 = 70015,
    services: u64 = 0,
    timestamp: i64,
    addr_recv_services: u64 = 0,
    addr_recv_ip: [16]u8 = [_]u8{0} ** 10 ++ [_]u8{0xff} ** 2 ++ [_]u8{0} ** 4,
    addr_recv_port: u16 = 8333,
    addr_trans_services: u64 = 0,
    addr_trans_ip: [16]u8 = [_]u8{0} ** 16,
    addr_trans_port: u16 = 8333,
    nonce: u64,
    user_agent: []const u8 = "/Yam:0.1.0/",
    start_height: i32 = 0,
    relay: bool = false,

    pub fn serialize(self: VersionPayload, writer: anytype) !void {
        try writer.writeInt(i32, self.version, .little);
        try writer.writeInt(u64, self.services, .little);
        try writer.writeInt(i64, self.timestamp, .little);

        // Receiver info
        try writer.writeInt(u64, self.addr_recv_services, .little);
        try writer.writeAll(&self.addr_recv_ip);
        try writer.writeInt(u16, self.addr_recv_port, .big); // Network Byte Order

        // Sender info
        try writer.writeInt(u64, self.addr_trans_services, .little);
        try writer.writeAll(&self.addr_trans_ip);
        try writer.writeInt(u16, self.addr_trans_port, .big); // Network Byte Order

        try writer.writeInt(u64, self.nonce, .little);

        // User Agent: CompactSize length + string bytes
        try writeVarInt(writer, self.user_agent.len);
        try writer.writeAll(self.user_agent);

        try writer.writeInt(i32, self.start_height, .little);
        try writer.writeByte(@intFromBool(self.relay));
    }

    pub fn deserialize(reader: anytype, allocator: std.mem.Allocator) !VersionPayload {
        const version = try reader.readInt(i32, .little);
        const services = try reader.readInt(u64, .little);
        const timestamp = try reader.readInt(i64, .little);

        // Receiver info
        const addr_recv_services = try reader.readInt(u64, .little);
        var addr_recv_ip: [16]u8 = undefined;
        _ = try reader.readAll(&addr_recv_ip);
        const addr_recv_port = try reader.readInt(u16, .big);

        // Sender info
        const addr_trans_services = try reader.readInt(u64, .little);
        var addr_trans_ip: [16]u8 = undefined;
        _ = try reader.readAll(&addr_trans_ip);
        const addr_trans_port = try reader.readInt(u16, .big);

        const nonce = try reader.readInt(u64, .little);

        // User Agent: CompactSize length + string bytes
        const user_agent_len = try readVarInt(reader);
        const user_agent = try allocator.alloc(u8, user_agent_len);
        errdefer allocator.free(user_agent);
        _ = try reader.readAll(user_agent);

        const start_height = try reader.readInt(i32, .little);
        const relay_byte = try reader.readByte();
        const relay = relay_byte != 0;

        return VersionPayload{
            .version = version,
            .services = services,
            .timestamp = timestamp,
            .addr_recv_services = addr_recv_services,
            .addr_recv_ip = addr_recv_ip,
            .addr_recv_port = addr_recv_port,
            .addr_trans_services = addr_trans_services,
            .addr_trans_ip = addr_trans_ip,
            .addr_trans_port = addr_trans_port,
            .nonce = nonce,
            .user_agent = user_agent,
            .start_height = start_height,
            .relay = relay,
        };
    }
};

// Inventory message types
pub const InvType = enum(u32) {
    msg_error = 0,
    msg_tx = 1, // Transaction
    msg_block = 2, // Block
    msg_filtered_block = 3, // Filtered block
    msg_cmpct_block = 4, // Compact block
    msg_witness_tx = 0x40000001, // Transaction with witness
    msg_witness_block = 0x40000002, // Block with witness
    msg_filtered_witness_block = 0x40000003, // Filtered block with witness
};

// Inventory vector: type + hash
pub const InvVector = struct {
    type: InvType,
    hash: [32]u8, // Transaction/block hash (reversed byte order)

    pub fn serialize(self: InvVector, writer: anytype) !void {
        try writer.writeInt(u32, @intFromEnum(self.type), .little);
        try writer.writeAll(&self.hash);
    }

    pub fn deserialize(reader: anytype) !InvVector {
        const type_raw = try reader.readInt(u32, .little);
        const inv_type: InvType = @enumFromInt(type_raw);

        var hash: [32]u8 = undefined;
        _ = try reader.readAll(&hash);

        return InvVector{
            .type = inv_type,
            .hash = hash,
        };
    }

    /// Convert hash to hex string (for display)
    /// Note: Bitcoin hashes are sent in little-endian, so this reverses them for display
    pub fn hashHex(self: InvVector) [64]u8 {
        return hashToHex(self.hash);
    }
};

// Inventory message (used by both 'inv' and 'getdata')
pub const InvMessage = struct {
    vectors: []InvVector,

    pub fn serialize(self: InvMessage, writer: anytype) !void {
        // Write count as CompactSize
        try writeVarInt(writer, self.vectors.len);

        // Write each inventory vector
        for (self.vectors) |vector| {
            try vector.serialize(writer);
        }
    }

    pub fn deserialize(reader: anytype, allocator: std.mem.Allocator) !InvMessage {
        // Read count as CompactSize
        const count = try readVarInt(reader);

        // Allocate array for vectors
        const vectors = try allocator.alloc(InvVector, count);
        errdefer allocator.free(vectors);

        // Read each vector
        for (vectors) |*vector| {
            vector.* = try InvVector.deserialize(reader);
        }

        return InvMessage{
            .vectors = vectors,
        };
    }

    pub fn deinit(self: InvMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.vectors);
    }
};

// Transaction Input
pub const TxInput = struct {
    prevout_hash: [32]u8, // Previous transaction hash (little-endian)
    prevout_index: u32, // Index of output in previous transaction
    script: []u8, // Unlocking script (signature script)
    sequence: u32, // Sequence number

    pub fn serialize(self: TxInput, writer: anytype) !void {
        try writer.writeAll(&self.prevout_hash);
        try writer.writeInt(u32, self.prevout_index, .little);
        try writeVarInt(writer, self.script.len);
        try writer.writeAll(self.script);
        try writer.writeInt(u32, self.sequence, .little);
    }

    pub fn deserialize(reader: anytype, allocator: std.mem.Allocator) !TxInput {
        // Read previous output hash
        var prevout_hash: [32]u8 = undefined;
        _ = try reader.readAll(&prevout_hash);

        // Read previous output index
        const prevout_index = try reader.readInt(u32, .little);

        // Read script length (CompactSize)
        const script_len = try readVarInt(reader);

        // Read script
        const script = try allocator.alloc(u8, script_len);
        errdefer allocator.free(script);
        _ = try reader.readAll(script);

        // Read sequence
        const sequence = try reader.readInt(u32, .little);

        return TxInput{
            .prevout_hash = prevout_hash,
            .prevout_index = prevout_index,
            .script = script,
            .sequence = sequence,
        };
    }

    pub fn deinit(self: TxInput, allocator: std.mem.Allocator) void {
        allocator.free(self.script);
    }

    /// Convert prevout hash to hex string (reversed for display)
    pub fn prevoutHashHex(self: TxInput) [64]u8 {
        return hashToHex(self.prevout_hash);
    }
};

// Transaction Output
pub const TxOutput = struct {
    value: u64, // Value in satoshis
    script: []u8, // Locking script (pubkey script)

    pub fn serialize(self: TxOutput, writer: anytype) !void {
        try writer.writeInt(u64, self.value, .little);
        try writeVarInt(writer, self.script.len);
        try writer.writeAll(self.script);
    }

    pub fn deserialize(reader: anytype, allocator: std.mem.Allocator) !TxOutput {
        // Read value (satoshis)
        const value = try reader.readInt(u64, .little);

        // Read script length (CompactSize)
        const script_len = try readVarInt(reader);

        // Read script
        const script = try allocator.alloc(u8, script_len);
        errdefer allocator.free(script);
        _ = try reader.readAll(script);

        return TxOutput{
            .value = value,
            .script = script,
        };
    }

    pub fn deinit(self: TxOutput, allocator: std.mem.Allocator) void {
        allocator.free(self.script);
    }

    /// Convert value to BTC (float)
    pub fn valueBtc(self: TxOutput) f64 {
        return @as(f64, @floatFromInt(self.value)) / 100_000_000.0;
    }
};

// Bitcoin Transaction
pub const Transaction = struct {
    version: i32,
    inputs: []TxInput,
    outputs: []TxOutput,
    locktime: u32,

    pub fn deserialize(reader: anytype, allocator: std.mem.Allocator) !Transaction {
        // Read version
        const version = try reader.readInt(i32, .little);

        // Read input count (CompactSize)
        const input_count = try readVarInt(reader);

        // Read inputs
        const inputs = try allocator.alloc(TxInput, input_count);
        errdefer {
            for (inputs) |*input| {
                input.deinit(allocator);
            }
            allocator.free(inputs);
        }

        for (inputs) |*input| {
            input.* = try TxInput.deserialize(reader, allocator);
        }

        // Read output count (CompactSize)
        const output_count = try readVarInt(reader);

        // Read outputs
        const outputs = try allocator.alloc(TxOutput, output_count);
        errdefer {
            for (outputs) |*output| {
                output.deinit(allocator);
            }
            allocator.free(outputs);
        }

        for (outputs) |*output| {
            output.* = try TxOutput.deserialize(reader, allocator);
        }

        // Read locktime
        const locktime = try reader.readInt(u32, .little);

        return Transaction{
            .version = version,
            .inputs = inputs,
            .outputs = outputs,
            .locktime = locktime,
        };
    }

    pub fn serialize(self: Transaction, writer: anytype) !void {
        try writer.writeInt(i32, self.version, .little);

        // Write input count
        try writeVarInt(writer, self.inputs.len);

        // Write inputs
        for (self.inputs) |input| {
            try input.serialize(writer);
        }

        // Write output count
        try writeVarInt(writer, self.outputs.len);

        // Write outputs
        for (self.outputs) |output| {
            try output.serialize(writer);
        }

        try writer.writeInt(u32, self.locktime, .little);
    }

    pub fn deinit(self: Transaction, allocator: std.mem.Allocator) void {
        for (self.inputs) |*input| {
            input.deinit(allocator);
        }
        allocator.free(self.inputs);

        for (self.outputs) |*output| {
            output.deinit(allocator);
        }
        allocator.free(self.outputs);
    }

    /// Calculate transaction ID (double SHA256 of serialized transaction)
    pub fn txid(self: Transaction, allocator: std.mem.Allocator) ![32]u8 {
        // Serialize transaction
        var buffer = std.ArrayList(u8).empty;
        defer buffer.deinit(allocator);
        try self.serialize(buffer.writer(allocator));

        // Calculate double SHA256
        var h1: [32]u8 = undefined;
        var h2: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(buffer.items, &h1, .{});
        std.crypto.hash.sha2.Sha256.hash(&h1, &h2, .{});

        return h2;
    }

    /// Get transaction ID as hex string (for display)
    pub fn txidHex(self: Transaction, allocator: std.mem.Allocator) ![64]u8 {
        const txid_bytes = try self.txid(allocator);
        return hashToHex(txid_bytes);
    }
};

fn writeVarInt(writer: anytype, value: u64) !void {
    if (value < 0xfd) {
        try writer.writeByte(@intCast(value));
    } else if (value <= 0xffff) {
        try writer.writeByte(0xfd);
        try writer.writeInt(u16, @intCast(value), .little);
    } else if (value <= 0xffffffff) {
        try writer.writeByte(0xfe);
        try writer.writeInt(u32, @intCast(value), .little);
    } else {
        try writer.writeByte(0xff);
        try writer.writeInt(u64, value, .little);
    }
}

fn readVarInt(reader: anytype) !u64 {
    const first_byte = try reader.readByte();
    if (first_byte < 0xfd) {
        return first_byte;
    } else if (first_byte == 0xfd) {
        return try reader.readInt(u16, .little);
    } else if (first_byte == 0xfe) {
        return try reader.readInt(u32, .little);
    } else {
        return try reader.readInt(u64, .little);
    }
}

/// Convert a 32-byte hash to hex string (reverses bytes for display)
/// Bitcoin hashes are sent in little-endian, so this reverses them for display
pub fn hashToHex(hash: [32]u8) [64]u8 {
    // Reverse hash for display (Bitcoin sends hashes in little-endian)
    var reversed_hash: [32]u8 = undefined;
    for (hash, 0..) |byte, i| {
        reversed_hash[31 - i] = byte;
    }

    // Convert to hex
    var hex: [64]u8 = undefined;
    for (reversed_hash, 0..) |byte, i| {
        const high: u8 = @intCast((byte >> 4) & 0x0f);
        const low: u8 = @intCast(byte & 0x0f);
        hex[i * 2] = if (high < 10) @as(u8, '0') + high else @as(u8, 'a') + (high - 10);
        hex[i * 2 + 1] = if (low < 10) @as(u8, '0') + low else @as(u8, 'a') + (low - 10);
    }
    return hex;
}

pub fn calculateChecksum(payload: []const u8) u32 {
    var h1: [32]u8 = undefined;
    var h2: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &h1, .{});
    std.crypto.hash.sha2.Sha256.hash(&h1, &h2, .{});
    // Return first 4 bytes as a little-endian u32
    return std.mem.readInt(u32, h2[0..4], .little);
}
