// message_utils.zig - Shared utilities for Bitcoin P2P message handling
// This module contains shared logic extracted from scout.zig and courier.zig
// to reduce code duplication and improve maintainability.

const std = @import("std");
const yam = @import("root.zig");

/// Maximum payload size for peer messages (4 MB)
/// This limit prevents memory exhaustion from malicious or misbehaving peers
pub const MAX_PAYLOAD_SIZE: u32 = 4_000_000;

/// Options for configuring message reading behavior
pub const ReadMessageOptions = struct {
    /// Maximum allowed payload size in bytes. If null, no limit is enforced.
    /// courier.zig enforces a 4 MB limit for stricter peer connection management.
    max_payload_size: ?u32 = null,

    /// Whether to verify the message checksum. If true, returns error.InvalidChecksum
    /// when the calculated checksum doesn't match the header checksum.
    verify_checksum: bool = false,
};

/// Result of reading a Bitcoin P2P protocol message
pub const Message = struct {
    header: yam.MessageHeader,
    payload: []u8,
};

/// Read a Bitcoin P2P protocol message from a stream
///
/// This function reads a 24-byte message header followed by the payload.
/// It handles partial reads and validates the magic number.
///
/// Caller is responsible for freeing the returned payload using the same allocator.
///
/// Parameters:
///   - stream: The network stream to read from
///   - allocator: Memory allocator for payload allocation
///   - options: Configuration options (payload size limit, checksum verification)
///
/// Returns: Message struct containing header and payload
///
/// Errors:
///   - ConnectionClosed: Stream closed before full message received
///   - InvalidMagic: Header magic number doesn't match Bitcoin mainnet (0xD9B4BEF9)
///   - PayloadTooLarge: Payload exceeds max_payload_size (if specified in options)
///   - InvalidChecksum: Checksum verification failed (if enabled in options)
pub fn readMessage(
    stream: std.net.Stream,
    allocator: std.mem.Allocator,
    options: ReadMessageOptions,
) !Message {
    // Read the 24-byte message header
    var header_buffer: [24]u8 align(4) = undefined;
    var total_read: usize = 0;
    while (total_read < header_buffer.len) {
        const bytes_read = try stream.read(header_buffer[total_read..]);
        if (bytes_read == 0) return error.ConnectionClosed;
        total_read += bytes_read;
    }

    // Parse header from buffer
    const header_ptr = std.mem.bytesAsValue(yam.MessageHeader, &header_buffer);
    const header = header_ptr.*;

    // Validate magic number (Bitcoin mainnet)
    if (header.magic != 0xD9B4BEF9) return error.InvalidMagic;

    // Read payload if present
    var payload: []u8 = &.{};
    if (header.length > 0) {
        // Enforce payload size limit if specified (e.g., 4 MB for courier.zig)
        if (options.max_payload_size) |max_size| {
            if (header.length > max_size) return error.PayloadTooLarge;
        }

        // Allocate buffer for payload
        payload = try allocator.alloc(u8, header.length);
        errdefer allocator.free(payload);

        // Read payload data (may require multiple reads)
        total_read = 0;
        while (total_read < header.length) {
            const bytes_read = try stream.read(payload[total_read..]);
            if (bytes_read == 0) {
                return error.ConnectionClosed;
            }
            total_read += bytes_read;
        }

        // Verify checksum if requested (used by courier.zig for individual peer connections)
        if (options.verify_checksum) {
            const calculated_checksum = yam.calculateChecksum(payload);
            if (calculated_checksum != header.checksum) {
                return error.InvalidChecksum;
            }
        }
    }

    return .{ .header = header, .payload = payload };
}
