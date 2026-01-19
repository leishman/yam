// Root.zig - Bitcoin P2P protocol implementation
// https://en.bitcoin.it/wiki/Protocol_documentation was used as the reference for this implementation.

const std = @import("std");
pub const network = @import("network.zig");

pub const MessageHeader = extern struct {
    magic: u32,
    command: [12]u8,
    length: u32,
    checksum: u32,

    pub fn new(cmd: []const u8, payload_len: u32, payload_checksum: u32) MessageHeader {
        var header = MessageHeader{
            .magic = network.magic,
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
    user_agent: []const u8 = "/Satoshi:27.0.0/",
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
        if (user_agent_len > 256) return error.UserAgentTooLong;
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
    _,
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
        if (count > 50000) return error.TooManyInvVectors;

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

// Reject message codes (BIP 61)
pub const RejectCode = enum(u8) {
    malformed = 0x01,
    invalid = 0x10,
    obsolete = 0x11,
    duplicate = 0x12,
    nonstandard = 0x40,
    dust = 0x41,
    insufficient_fee = 0x42,
    checkpoint = 0x43,
    _,

    pub fn toString(self: RejectCode) []const u8 {
        return switch (self) {
            .malformed => "REJECT_MALFORMED",
            .invalid => "REJECT_INVALID",
            .obsolete => "REJECT_OBSOLETE",
            .duplicate => "REJECT_DUPLICATE",
            .nonstandard => "REJECT_NONSTANDARD",
            .dust => "REJECT_DUST",
            .insufficient_fee => "REJECT_INSUFFICIENTFEE",
            .checkpoint => "REJECT_CHECKPOINT",
            _ => "REJECT_UNKNOWN",
        };
    }
};

// Reject message (BIP 61)
pub const RejectMessage = struct {
    message: []u8, // Type of message rejected (e.g., "tx", "block")
    code: RejectCode,
    reason: []u8, // Human-readable rejection reason
    data: []u8, // Optional extra data (e.g., txid for tx rejections)

    pub fn deserialize(reader: anytype, allocator: std.mem.Allocator) !RejectMessage {
        // Read message type (var_str)
        const msg_len = try readVarInt(reader);
        if (msg_len > 12) return error.RejectMessageTooLong;
        const message = try allocator.alloc(u8, msg_len);
        errdefer allocator.free(message);
        _ = try reader.readAll(message);

        // Read reject code
        const code: RejectCode = @enumFromInt(try reader.readByte());

        // Read reason (var_str)
        const reason_len = try readVarInt(reader);
        if (reason_len > 111) return error.RejectReasonTooLong;
        const reason = try allocator.alloc(u8, reason_len);
        errdefer allocator.free(reason);
        _ = try reader.readAll(reason);

        // Read extra data (rest of payload - typically 32 bytes for tx hash)
        // We'll read what's available
        var data_list = std.ArrayList(u8).empty;
        errdefer data_list.deinit(allocator);
        while (true) {
            const byte = reader.readByte() catch break;
            try data_list.append(allocator, byte);
        }
        const data = try data_list.toOwnedSlice(allocator);

        return RejectMessage{
            .message = message,
            .code = code,
            .reason = reason,
            .data = data,
        };
    }

    pub fn deinit(self: RejectMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.message);
        allocator.free(self.reason);
        allocator.free(self.data);
    }

    pub fn format(self: RejectMessage, allocator: std.mem.Allocator) ![]u8 {
        var result = std.ArrayList(u8).empty;
        const writer = result.writer(allocator);

        try writer.print("{s} {s}: {s}", .{ self.message, self.code.toString(), self.reason });

        // If data is 32 bytes, it's likely a txid
        if (self.data.len == 32) {
            const hex = hashToHex(self.data[0..32].*);
            try writer.print(" (txid: {s})", .{hex});
        }

        return result.toOwnedSlice(allocator);
    }
};

// Transaction Input
pub const TxInput = struct {
    prevout_hash: [32]u8, // Previous transaction hash (little-endian)
    prevout_index: u32, // Index of output in previous transaction
    script: []u8, // Unlocking script (signature script)
    sequence: u32, // Sequence number
    witness: [][]u8, // Witness stack (empty for non-segwit)

    pub fn serialize(self: TxInput, writer: anytype) !void {
        try writer.writeAll(&self.prevout_hash);
        try writer.writeInt(u32, self.prevout_index, .little);
        try writeVarInt(writer, self.script.len);
        try writer.writeAll(self.script);
        try writer.writeInt(u32, self.sequence, .little);
    }

    pub fn serializeWitness(self: TxInput, writer: anytype) !void {
        try writeVarInt(writer, self.witness.len);
        for (self.witness) |item| {
            try writeVarInt(writer, item.len);
            try writer.writeAll(item);
        }
    }

    pub fn deserialize(reader: anytype, allocator: std.mem.Allocator) !TxInput {
        // Read previous output hash
        var prevout_hash: [32]u8 = undefined;
        _ = try reader.readAll(&prevout_hash);

        // Read previous output index
        const prevout_index = try reader.readInt(u32, .little);

        // Read script length (CompactSize)
        const script_len = try readVarInt(reader);
        if (script_len > 10000) return error.ScriptTooLarge;

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
            .witness = &.{}, // Witness is read separately for SegWit txs
        };
    }

    pub fn deinit(self: TxInput, allocator: std.mem.Allocator) void {
        allocator.free(self.script);
        for (self.witness) |item| {
            allocator.free(item);
        }
        if (self.witness.len > 0) {
            allocator.free(self.witness);
        }
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
        if (script_len > 10000) return error.ScriptTooLarge;

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

        // Check for SegWit marker (0x00) and flag (0x01)
        const marker = try reader.readByte();
        var is_segwit = false;
        var input_count: u64 = undefined;

        if (marker == 0x00) {
            const flag = try reader.readByte();
            if (flag != 0x01) {
                return error.InvalidSegwitFlag;
            }
            is_segwit = true;
            input_count = try readVarInt(reader);
        } else {
            // Not SegWit - marker was actually the first byte of input_count varint
            if (marker < 0xfd) {
                input_count = marker;
            } else if (marker == 0xfd) {
                input_count = try reader.readInt(u16, .little);
            } else if (marker == 0xfe) {
                input_count = try reader.readInt(u32, .little);
            } else {
                input_count = try reader.readInt(u64, .little);
            }
        }

        // Read inputs
        const inputs = try allocator.alloc(TxInput, input_count);
        var inputs_initialized: usize = 0;
        errdefer {
            for (inputs[0..inputs_initialized]) |*input| {
                input.deinit(allocator);
            }
            allocator.free(inputs);
        }

        for (inputs) |*input| {
            input.* = try TxInput.deserialize(reader, allocator);
            inputs_initialized += 1;
        }

        // Read output count (CompactSize)
        const output_count = try readVarInt(reader);

        // Read outputs
        const outputs = try allocator.alloc(TxOutput, output_count);
        var outputs_initialized: usize = 0;
        errdefer {
            for (outputs[0..outputs_initialized]) |*output| {
                output.deinit(allocator);
            }
            allocator.free(outputs);
        }

        for (outputs) |*output| {
            output.* = try TxOutput.deserialize(reader, allocator);
            outputs_initialized += 1;
        }

        // Read witness data for SegWit transactions
        if (is_segwit) {
            for (inputs) |*input| {
                const witness_count = try readVarInt(reader);
                if (witness_count > 500) return error.TooManyWitnessItems;
                const witness = try allocator.alloc([]u8, witness_count);
                var witness_initialized: usize = 0;
                errdefer {
                    for (witness[0..witness_initialized]) |item| {
                        allocator.free(item);
                    }
                    allocator.free(witness);
                }

                for (witness) |*item| {
                    const item_len = try readVarInt(reader);
                    if (item_len > 520) return error.WitnessItemTooLarge;
                    item.* = try allocator.alloc(u8, item_len);
                    errdefer allocator.free(item.*);
                    _ = try reader.readAll(item.*);
                    witness_initialized += 1;
                }
                input.witness = witness;
            }
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

    /// Check if this transaction has witness data
    pub fn hasWitness(self: Transaction) bool {
        for (self.inputs) |input| {
            if (input.witness.len > 0) return true;
        }
        return false;
    }

    /// Serialize in legacy format (for txid calculation)
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

    /// Serialize with witness data (for wtxid calculation and network transmission)
    pub fn serializeWitness(self: Transaction, writer: anytype) !void {
        try writer.writeInt(i32, self.version, .little);

        // Write marker and flag for SegWit
        if (self.hasWitness()) {
            try writer.writeByte(0x00); // marker
            try writer.writeByte(0x01); // flag
        }

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

        // Write witness data if present
        if (self.hasWitness()) {
            for (self.inputs) |input| {
                try input.serializeWitness(writer);
            }
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

pub fn writeVarInt(writer: anytype, value: u64) !void {
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

// Peer information for connection management
pub const PeerSource = enum {
    dns_seed,
    addr_message,
    cli_manual,
    hardcoded_fallback,
};

pub const PeerInfo = struct {
    address: std.net.Address,
    services: u64 = 0,
    source: PeerSource,

    pub fn format(self: PeerInfo) [21]u8 {
        var buf: [21]u8 = [_]u8{' '} ** 21;
        switch (self.address.any.family) {
            std.posix.AF.INET => {
                const addr = self.address.in;
                const ip_bytes = @as(*const [4]u8, @ptrCast(&addr.sa.addr));
                _ = std.fmt.bufPrint(&buf, "{d}.{d}.{d}.{d}:{d}", .{
                    ip_bytes[0],
                    ip_bytes[1],
                    ip_bytes[2],
                    ip_bytes[3],
                    std.mem.bigToNative(u16, addr.sa.port),
                }) catch {};
            },
            else => {
                _ = std.fmt.bufPrint(&buf, "<ipv6>", .{}) catch {};
            },
        }
        return buf;
    }
};

// Bitcoin network address (used in addr messages)
pub const NetAddr = struct {
    time: u32, // Timestamp (not present in version msg)
    services: u64,
    ip: [16]u8, // IPv6-mapped IPv4 or IPv6
    port: u16,

    pub fn deserialize(reader: anytype) !NetAddr {
        return .{
            .time = try reader.readInt(u32, .little),
            .services = try reader.readInt(u64, .little),
            .ip = try reader.readBytesNoEof(16),
            .port = try reader.readInt(u16, .big),
        };
    }

    pub fn toAddress(self: NetAddr) ?std.net.Address {
        // Check if IPv6-mapped IPv4 (::ffff:x.x.x.x)
        const ipv4_prefix = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff };
        if (std.mem.eql(u8, self.ip[0..12], &ipv4_prefix)) {
            // IPv4
            return std.net.Address.initIp4(self.ip[12..16].*, self.port);
        } else {
            // IPv6 - for now we skip these
            return null;
        }
    }

    pub fn toPeerInfo(self: NetAddr, source: PeerSource) ?PeerInfo {
        const addr = self.toAddress() orelse return null;
        return PeerInfo{
            .address = addr,
            .services = self.services,
            .source = source,
        };
    }
};

// Addr message (list of peer addresses)
pub const AddrMessage = struct {
    addresses: []NetAddr,

    pub fn deserialize(reader: anytype, allocator: std.mem.Allocator) !AddrMessage {
        const count = try readVarInt(reader);
        // Limit to reasonable number to prevent memory issues
        if (count > 1000) return error.TooManyAddresses;

        const addresses = try allocator.alloc(NetAddr, count);
        errdefer allocator.free(addresses);

        for (addresses) |*addr| {
            addr.* = try NetAddr.deserialize(reader);
        }

        return .{ .addresses = addresses };
    }

    pub fn deinit(self: AddrMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.addresses);
    }
};

// Convert hex string to bytes
pub fn hexToBytes(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.InvalidHexLength;

    const bytes = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(bytes);

    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        bytes[i / 2] = std.fmt.parseInt(u8, hex[i..][0..2], 16) catch return error.InvalidHexChar;
    }

    return bytes;
}

// ============================================================================
// Tests
// ============================================================================

test "hexToBytes valid input" {
    const allocator = std.testing.allocator;

    const bytes = try hexToBytes(allocator, "deadbeef");
    defer allocator.free(bytes);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xde, 0xad, 0xbe, 0xef }, bytes);
}

test "hexToBytes empty string" {
    const allocator = std.testing.allocator;

    const bytes = try hexToBytes(allocator, "");
    defer allocator.free(bytes);

    try std.testing.expectEqual(@as(usize, 0), bytes.len);
}

test "hexToBytes odd length returns error" {
    const allocator = std.testing.allocator;

    const result = hexToBytes(allocator, "abc");
    try std.testing.expectError(error.InvalidHexLength, result);
}

test "hexToBytes invalid hex char returns error" {
    const allocator = std.testing.allocator;

    const result = hexToBytes(allocator, "ghij");
    try std.testing.expectError(error.InvalidHexChar, result);
}

test "calculateChecksum" {
    // Verify checksum is deterministic and non-zero for non-empty data
    const checksum1 = calculateChecksum("hello");
    const checksum2 = calculateChecksum("hello");
    try std.testing.expectEqual(checksum1, checksum2);

    // Different data should produce different checksums
    const checksum3 = calculateChecksum("world");
    try std.testing.expect(checksum1 != checksum3);

    // Empty payload should produce a valid checksum
    const empty_checksum = calculateChecksum(&[_]u8{});
    _ = empty_checksum; // Just verify it doesn't crash
}

test "MessageHeader creation" {
    const header = MessageHeader.new("version", 100, 0x12345678);

    try std.testing.expectEqual(@as(u32, 0xD9B4BEF9), header.magic);
    try std.testing.expectEqualSlices(u8, "version\x00\x00\x00\x00\x00", &header.command);
    try std.testing.expectEqual(@as(u32, 100), header.length);
    try std.testing.expectEqual(@as(u32, 0x12345678), header.checksum);
}

test "MessageHeader command padding" {
    const header = MessageHeader.new("tx", 0, 0);

    // "tx" should be null-padded to 12 bytes
    try std.testing.expectEqualSlices(u8, "tx\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", &header.command);
}

test "VarInt encoding single byte" {
    var buf: [9]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    try writeVarInt(fbs.writer(), 0);
    try std.testing.expectEqual(@as(usize, 1), fbs.pos);
    try std.testing.expectEqual(@as(u8, 0), buf[0]);

    fbs.pos = 0;
    try writeVarInt(fbs.writer(), 0xFC);
    try std.testing.expectEqual(@as(usize, 1), fbs.pos);
    try std.testing.expectEqual(@as(u8, 0xFC), buf[0]);
}

test "VarInt encoding two bytes" {
    var buf: [9]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    try writeVarInt(fbs.writer(), 0xFD);
    try std.testing.expectEqual(@as(usize, 3), fbs.pos);
    try std.testing.expectEqual(@as(u8, 0xFD), buf[0]);
    // Little-endian 0x00FD
    try std.testing.expectEqual(@as(u8, 0xFD), buf[1]);
    try std.testing.expectEqual(@as(u8, 0x00), buf[2]);
}

test "VarInt encoding four bytes" {
    var buf: [9]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    try writeVarInt(fbs.writer(), 0x10000);
    try std.testing.expectEqual(@as(usize, 5), fbs.pos);
    try std.testing.expectEqual(@as(u8, 0xFE), buf[0]);
}

test "VarInt round-trip" {
    const allocator = std.testing.allocator;
    _ = allocator;

    const test_values = [_]u64{ 0, 1, 0xFC, 0xFD, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000 };

    for (test_values) |val| {
        var buf: [9]u8 = undefined;
        var write_fbs = std.io.fixedBufferStream(&buf);
        try writeVarInt(write_fbs.writer(), val);

        var read_fbs = std.io.fixedBufferStream(buf[0..write_fbs.pos]);
        const read_val = try readVarInt(read_fbs.reader());

        try std.testing.expectEqual(val, read_val);
    }
}

test "ServiceFlags decode" {
    // NODE_NETWORK=0x01 | NODE_BLOOM=0x04 | NODE_WITNESS=0x08 | NODE_COMPACT_FILTERS=0x2000
    const flags = ServiceFlags.decode(0x200d);

    try std.testing.expect(flags.network);
    try std.testing.expect(!flags.getutxo);
    try std.testing.expect(flags.bloom);
    try std.testing.expect(flags.witness);
    try std.testing.expect(!flags.network_limited);
    try std.testing.expect(flags.compact_filters);
}

test "ServiceFlags decode minimal" {
    // Just NODE_NETWORK
    const flags = ServiceFlags.decode(0x01);

    try std.testing.expect(flags.network);
    try std.testing.expect(!flags.bloom);
    try std.testing.expect(!flags.witness);
}

test "hashToHex conversion" {
    const hash = [_]u8{0} ** 31 ++ [_]u8{0x01};
    const hex = hashToHex(hash);

    // Hash is reversed for display, so 0x01 at end becomes "01" at start
    try std.testing.expectEqualSlices(u8, "01", hex[0..2]);
}

test "TxOutput valueBtc conversion" {
    const output = TxOutput{
        .value = 100_000_000, // 1 BTC in satoshis
        .script = &[_]u8{},
    };

    try std.testing.expectEqual(@as(f64, 1.0), output.valueBtc());
}

test "TxOutput valueBtc small amount" {
    const output = TxOutput{
        .value = 1, // 1 satoshi
        .script = &[_]u8{},
    };

    try std.testing.expectApproxEqAbs(@as(f64, 0.00000001), output.valueBtc(), 1e-12);
}

test "Transaction serialize and deserialize round-trip" {
    const allocator = std.testing.allocator;

    // Create a minimal valid transaction
    const input_script = try allocator.alloc(u8, 4);
    @memcpy(input_script, &[_]u8{ 0x01, 0x02, 0x03, 0x04 });

    const output_script = try allocator.alloc(u8, 2);
    @memcpy(output_script, &[_]u8{ 0xaa, 0xbb });

    const inputs = try allocator.alloc(TxInput, 1);
    inputs[0] = TxInput{
        .prevout_hash = [_]u8{0xde} ** 32,
        .prevout_index = 0,
        .script = input_script,
        .sequence = 0xFFFFFFFF,
        .witness = &.{},
    };

    const outputs = try allocator.alloc(TxOutput, 1);
    outputs[0] = TxOutput{
        .value = 50000,
        .script = output_script,
    };

    const tx = Transaction{
        .version = 1,
        .inputs = inputs,
        .outputs = outputs,
        .locktime = 0,
    };
    defer tx.deinit(allocator);

    // Serialize
    var serialized = std.ArrayList(u8).empty;
    defer serialized.deinit(allocator);
    try tx.serialize(serialized.writer(allocator));

    // Deserialize
    var fbs = std.io.fixedBufferStream(serialized.items);
    const tx2 = try Transaction.deserialize(fbs.reader(), allocator);
    defer tx2.deinit(allocator);

    // Verify
    try std.testing.expectEqual(tx.version, tx2.version);
    try std.testing.expectEqual(tx.locktime, tx2.locktime);
    try std.testing.expectEqual(tx.inputs.len, tx2.inputs.len);
    try std.testing.expectEqual(tx.outputs.len, tx2.outputs.len);
    try std.testing.expectEqual(tx.inputs[0].prevout_index, tx2.inputs[0].prevout_index);
    try std.testing.expectEqual(tx.outputs[0].value, tx2.outputs[0].value);
}

test "PeerInfo format IPv4" {
    const addr = std.net.Address.parseIp4("192.168.1.1", 8333) catch unreachable;
    const peer = PeerInfo{
        .address = addr,
        .source = .dns_seed,
    };

    const formatted = peer.format();
    const trimmed = std.mem.sliceTo(&formatted, ' ');

    try std.testing.expectEqualSlices(u8, "192.168.1.1:8333", trimmed);
}

test "NetAddr IPv4-mapped detection" {
    // IPv4-mapped IPv6: ::ffff:192.168.1.1
    const net_addr = NetAddr{
        .time = 0,
        .services = 0,
        .ip = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff, 192, 168, 1, 1 },
        .port = 8333,
    };

    const addr = net_addr.toAddress();
    try std.testing.expect(addr != null);

    const peer = net_addr.toPeerInfo(.addr_message);
    try std.testing.expect(peer != null);
    try std.testing.expectEqual(PeerSource.addr_message, peer.?.source);
}

test "NetAddr pure IPv6 returns null" {
    // Pure IPv6 address (not IPv4-mapped)
    const net_addr = NetAddr{
        .time = 0,
        .services = 0,
        .ip = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 12,
        .port = 8333,
    };

    const addr = net_addr.toAddress();
    try std.testing.expect(addr == null);
}

test "InvMessage deserialize" {
    const allocator = std.testing.allocator;

    // Create a minimal inv message: 1 item, type=TX(1), hash=zeros
    var buf: [37]u8 = undefined;
    buf[0] = 1; // count (varint)
    std.mem.writeInt(u32, buf[1..5], 1, .little); // type = MSG_TX
    @memset(buf[5..37], 0xab); // hash

    var fbs = std.io.fixedBufferStream(&buf);
    const inv = try InvMessage.deserialize(fbs.reader(), allocator);
    defer inv.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), inv.vectors.len);
    try std.testing.expectEqual(InvType.msg_tx, inv.vectors[0].type);
}

test "SegWit transaction txid - BIP 143 test vector" {
    const allocator = std.testing.allocator;

    // BIP 143 Native P2WPKH test vector (signed transaction)
    const raw_hex = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000";
    const expected_txid = "e8151a2af31c368a35053ddd4bdb285a8595c769a3ad83e0fa02314a602d4609";

    const tx_bytes = try hexToBytes(allocator, raw_hex);
    defer allocator.free(tx_bytes);

    var fbs = std.io.fixedBufferStream(tx_bytes);
    const tx = try Transaction.deserialize(fbs.reader(), allocator);
    defer tx.deinit(allocator);

    // Verify it parsed as SegWit (has witness data)
    try std.testing.expect(tx.hasWitness());
    try std.testing.expectEqual(@as(usize, 2), tx.inputs.len);
    try std.testing.expectEqual(@as(usize, 2), tx.outputs.len);

    // First input has empty witness, second has 2 items
    try std.testing.expectEqual(@as(usize, 0), tx.inputs[0].witness.len);
    try std.testing.expectEqual(@as(usize, 2), tx.inputs[1].witness.len);

    // Calculate txid and verify
    const txid_hex = try tx.txidHex(allocator);
    try std.testing.expectEqualSlices(u8, expected_txid, &txid_hex);
}
