const std = @import("std");
const yam = @import("yam");

pub fn main() !void {
    // setup allocator
    var allocator = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        const result = allocator.deinit();
        if (result == .leak) {
            std.debug.print("Memory leak detected\n", .{});
        }
    }

    const gpa_allocator = allocator.allocator();

    const ip = "172.7.56.107";

    // hardcode node IP (TODO: update)
    const peer_addr = try std.net.Address.parseIp4(ip, 8333);

    // setup TCP stream with node
    std.debug.print("Connecting to peer: {s}\n", .{ip});

    // initialize tcp connection with node
    var stream = try std.net.tcpConnectToAddress(peer_addr);
    defer stream.close();

    std.debug.print("Starting handshake", .{});

    try performHandshake(stream, gpa_allocator);

    // Request existing mempool transactions, not new ones
    // std.debug.print("\n>>> Requesting mempool transactions...\n", .{});
    // try sendMessage(stream, "mempool", &.{});

    // Listen for new mempool transactions
    std.debug.print("=== Listening for mempool transactions ===\n", .{});
    std.debug.print("Note: Some nodes may close connections to lightweight clients.\n", .{});
    std.debug.print("If connection closes, transactions may still arrive before disconnect.\n\n", .{});

    listenForMempool(stream, gpa_allocator) catch |err| {
        std.debug.print("\nConnection ended: {}\n", .{err});
        std.debug.print("This is normal - many Bitcoin nodes close lightweight client connections.\n", .{});
        std.debug.print("Try connecting to a different node or wait for transactions before disconnect.\n", .{});
    };
}

fn listenForMempool(stream: std.net.Stream, allocator: std.mem.Allocator) !void {
    var message_count: usize = 0;

    while (true) {
        const message = readMessage(stream, allocator) catch |err| {
            if (err == error.ConnectionClosed) {
                std.debug.print("\nConnection closed by peer (received {d} messages)\n", .{message_count});
                return err;
            }
            return err;
        };
        defer if (message.payload.len > 0) allocator.free(message.payload);

        message_count += 1;
        const cmd = std.mem.sliceTo(&message.header.command, 0);

        if (std.mem.eql(u8, cmd, "inv")) {
            const inv_msg = try parseInvMessage(message.payload, allocator);
            // TODO: might not even need this function
            try handleInvMessage(&inv_msg);
            // request the data for the vectors

            // send the message payload right back with the getdata command
            try sendMessage(stream, "getdata", message.payload);
            // try getDataForVectors(stream, msg.payload, allocator);
            defer inv_msg.deinit(allocator);
            // try getDataForVectors(, allocator);
        } else if (std.mem.eql(u8, cmd, "ping")) {
            // pong is not needed for mempool listening
            // Respond to ping with pong
            // std.debug.print(">>> Received ping, sending pong...\n", .{});
            // Ping payload is 8 bytes nonce, pong echoes it back
            // try sendMessage(stream, "pong", message.payload);
        } else if (std.mem.eql(u8, cmd, "sendcmpct")) {
            std.debug.print("<<< Received sendcmpct (compact blocks support)\n", .{});
            // No response needed - peer is informing us they support compact blocks
        } else if (std.mem.eql(u8, cmd, "feefilter")) {
            std.debug.print("<<< Received feefilter (minimum fee: {d} sat/kB)\n", .{message.payload.len});
            // No response needed - peer is setting minimum fee filter
        } else if (std.mem.eql(u8, cmd, "addr")) {
            std.debug.print("<<< Received addr (peer addresses)\n", .{});
        } else if (std.mem.eql(u8, cmd, "tx")) {
            try handleTxMessage(message.payload, allocator);
        } else if (std.mem.eql(u8, cmd, "reject")) {
            std.debug.print("<<< Received reject message\n", .{});
        } else {
            std.debug.print("<<< Received: {s} (len: {d})\n", .{ cmd, message.header.length });
        }
    }
}

fn parseInvMessage(payload: []const u8, allocator: std.mem.Allocator) !yam.InvMessage {
    var fbs = std.io.fixedBufferStream(payload);
    return yam.InvMessage.deserialize(fbs.reader(), allocator);
}

fn handleInvMessage(inv_msg: *const yam.InvMessage) !void {
    std.debug.print("<<< Received inv message with {d} items\n", .{inv_msg.vectors.len});

    var tx_count: usize = 0;
    for (inv_msg.vectors) |vector| {
        const hex = vector.hashHex();

        switch (vector.type) {
            .msg_tx, .msg_witness_tx => {
                tx_count += 1;
                std.debug.print("  TX: {s}\n", .{hex});
            },
            .msg_block, .msg_witness_block, .msg_filtered_block, .msg_filtered_witness_block => {
                std.debug.print("  BLOCK: {s}\n", .{hex});
            },
            else => {
                std.debug.print("  UNKNOWN TYPE ({d}): {s}\n", .{ @intFromEnum(vector.type), hex });
            },
        }
    }

    if (tx_count > 0) {
        std.debug.print("Found {d} transaction(s) in mempool\n", .{tx_count});
    }
}

fn handleTxMessage(payload: []const u8, allocator: std.mem.Allocator) !void {
    var fbs = std.io.fixedBufferStream(payload);
    const tx = try yam.Transaction.deserialize(fbs.reader(), allocator);
    defer tx.deinit(allocator);

    // Calculate and display txid
    const txid_hex = try tx.txidHex(allocator);

    std.debug.print("\n=== Transaction ===\n", .{});
    std.debug.print("TXID: {s}\n", .{txid_hex});
    std.debug.print("Version: {d}\n", .{tx.version});
    std.debug.print("Inputs: {d}\n", .{tx.inputs.len});
    std.debug.print("Outputs: {d}\n", .{tx.outputs.len});
    std.debug.print("Locktime: {d}\n", .{tx.locktime});

    // Display inputs
    if (tx.inputs.len > 0) {
        std.debug.print("\nInputs:\n", .{});
        for (tx.inputs, 0..) |input, i| {
            const hash_hex = input.prevoutHashHex();
            std.debug.print("  [{d}] Prevout: {s}:{d}\n", .{ i, hash_hex, input.prevout_index });
            std.debug.print("       Script length: {d} bytes\n", .{input.script.len});
            std.debug.print("       Sequence: 0x{x}\n", .{input.sequence});
        }
    }

    // Display outputs
    if (tx.outputs.len > 0) {
        std.debug.print("\nOutputs:\n", .{});
        var total_output: u64 = 0;
        for (tx.outputs, 0..) |output, i| {
            const btc = output.valueBtc();
            total_output += output.value;
            std.debug.print("  [{d}] {d:.8} BTC ({d} satoshis)\n", .{ i, btc, output.value });
            std.debug.print("       Script length: {d} bytes\n", .{output.script.len});
        }
        const total_btc = @as(f64, @floatFromInt(total_output)) / 100_000_000.0;
        std.debug.print("\nTotal output: {d:.8} BTC ({d} satoshis)\n", .{ total_btc, total_output });
    }

    std.debug.print("\n", .{});
}

fn readMessage(stream: std.net.Stream, allocator: std.mem.Allocator) !struct { header: yam.MessageHeader, payload: []u8 } {
    // Read header
    var header_buffer: [24]u8 align(4) = undefined;
    var total_read: usize = 0;
    while (total_read < header_buffer.len) {
        const bytes_read = try stream.read(header_buffer[total_read..]);
        if (bytes_read == 0) {
            return error.ConnectionClosed;
        }
        total_read += bytes_read;
    }

    const header_ptr = std.mem.bytesAsValue(yam.MessageHeader, &header_buffer);
    const header = header_ptr.*;

    // Verify magic number
    if (header.magic != 0xD9B4BEF9) {
        std.debug.print("Invalid magic number: 0x{x}\n", .{header.magic});
        return error.InvalidMagic;
    }

    // Read payload if present
    var payload: []u8 = &.{};
    if (header.length > 0) {
        payload = try allocator.alloc(u8, header.length);
        errdefer allocator.free(payload);

        total_read = 0;
        while (total_read < header.length) {
            const bytes_read = try stream.read(payload[total_read..]);
            if (bytes_read == 0) {
                allocator.free(payload);
                return error.ConnectionClosed;
            }
            total_read += bytes_read;
        }

        // Verify checksum
        const calculated_checksum = yam.calculateChecksum(payload);
        if (calculated_checksum != header.checksum) {
            allocator.free(payload);
            std.debug.print("Checksum mismatch: expected 0x{x}, got 0x{x}\n", .{ header.checksum, calculated_checksum });
            return error.InvalidChecksum;
        }
    }

    return .{ .header = header, .payload = payload };
}

fn sendMessage(stream: std.net.Stream, command: []const u8, payload: []const u8) !void {
    const checksum = yam.calculateChecksum(payload);
    const header = yam.MessageHeader.new(command, @intCast(payload.len), checksum);

    try stream.writeAll(std.mem.asBytes(&header));
    if (payload.len > 0) {
        try stream.writeAll(payload);
    }
}

fn performHandshake(stream: std.net.Stream, allocator: std.mem.Allocator) !void {
    // Generate random nonce
    var nonce: u64 = undefined;
    try std.posix.getrandom(std.mem.asBytes(&nonce));

    // Create and send version message
    // Set relay=true to receive transaction relay messages
    const version_payload = yam.VersionPayload{
        .timestamp = std.time.timestamp(),
        .nonce = nonce,
        .relay = true, // Enable transaction relay
    };

    var payload_buffer = std.ArrayList(u8).empty;
    defer payload_buffer.deinit(allocator);
    try version_payload.serialize(payload_buffer.writer(allocator));

    std.debug.print(">>> Sending version message...\n", .{});
    try sendMessage(stream, "version", payload_buffer.items);

    // Track handshake state
    var received_version = false;
    var received_verack = false;

    // Wait for version and verack (can arrive in any order)
    while (!received_version or !received_verack) {
        const message = try readMessage(stream, allocator);
        defer if (message.payload.len > 0) allocator.free(message.payload);

        const cmd = std.mem.sliceTo(&message.header.command, 0);
        std.debug.print("<<< Received: {s} (len: {d})\n", .{ cmd, message.header.length });

        if (std.mem.eql(u8, cmd, "version")) {
            if (received_version) {
                std.debug.print("Warning: Duplicate version message received\n", .{});
                continue;
            }
            received_version = true;

            // Parse version payload
            var fbs = std.io.fixedBufferStream(message.payload);
            const peer_version = try yam.VersionPayload.deserialize(fbs.reader(), allocator);
            defer allocator.free(peer_version.user_agent);

            std.debug.print("Peer version: {d}\n", .{peer_version.version});
            std.debug.print("Peer services: 0x{x}\n", .{peer_version.services});

            // Decode service flags
            const services = yam.ServiceFlags.decode(peer_version.services);
            std.debug.print("  Service flags:\n", .{});
            if (services.network) std.debug.print("    - NODE_NETWORK (full node)\n", .{});
            if (services.bloom) std.debug.print("    - NODE_BLOOM (Bloom filter support - good for lightweight clients!)\n", .{});
            if (services.witness) std.debug.print("    - NODE_WITNESS (SegWit support)\n", .{});
            if (services.network_limited) std.debug.print("    - NODE_NETWORK_LIMITED (pruned node)\n", .{});
            if (services.compact_filters) std.debug.print("    - NODE_COMPACT_FILTERS (BIP157/158 support)\n", .{});
            if (services.getutxo) std.debug.print("    - NODE_GETUTXO\n", .{});

            std.debug.print("Peer user agent: {s}\n", .{peer_version.user_agent});
            std.debug.print("Peer start height: {d}\n", .{peer_version.start_height});
            std.debug.print("Peer nonce: 0x{x}\n", .{peer_version.nonce});

            // Check if node is lightweight-client friendly
            if (services.bloom) {
                std.debug.print("\n✓ Node supports Bloom filters - should be friendly to lightweight clients!\n", .{});
            } else if (services.network) {
                std.debug.print("\n⚠ Node is a full node but may not support lightweight clients\n", .{});
            }

            // Send verack
            std.debug.print(">>> Sending verack...\n", .{});
            try sendMessage(stream, "verack", &.{});
        } else if (std.mem.eql(u8, cmd, "verack")) {
            if (received_verack) {
                std.debug.print("Warning: Duplicate verack message received\n", .{});
                continue;
            }
            received_verack = true;
            std.debug.print("Handshake complete! Connection established.\n", .{});
        } else {
            std.debug.print("Unexpected message during handshake: {s}\n", .{cmd});
            // Continue waiting for version/verack
        }
    }
}

test "simple test" {
    const gpa = std.testing.allocator;
    var list: std.ArrayList(i32) = .empty;
    defer list.deinit(gpa); // Try commenting this out and see if zig detects the memory leak!
    try list.append(gpa, 42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}

test "fuzz example" {
    const Context = struct {
        fn testOne(context: @This(), input: []const u8) anyerror!void {
            _ = context;
            // Try passing `--fuzz` to `zig build test` and see if it manages to fail this test case!
            try std.testing.expect(!std.mem.eql(u8, "canyoufindme", input));
        }
    };
    try std.testing.fuzz(Context{}, Context.testOne, .{});
}
