// Network.zig - Network configuration (mainnet/signet)
//
// Usage: yam --signet <challenge_hex> [command]
//
// These are "set once at startup" static variables - never modified after init.

const std = @import("std");

// ---------------------------------------------------------------------------
// Static network configuration (set once at startup, never modified after)
// ---------------------------------------------------------------------------

/// Public signet challenge (Bitcoin Core default)
pub const default_signet_challenge_hex =
    "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae";

/// Public signet DNS seeds (Bitcoin Core default)
pub const signet_dns_seeds = [_][]const u8{
    "seed.signet.bitcoin.sprovoost.nl",
    "seed.signet.achownodes.xyz",
};

/// Network magic bytes (mainnet: 0xD9B4BEF9, signet: computed from challenge)
pub var magic: u32 = 0xD9B4BEF9;

/// Default P2P port (mainnet: 8333, signet: 38333)
pub var default_port: u16 = 8333;

/// Whether we're running in signet mode
pub var is_signet: bool = false;

/// Whether to use DNS seeds for signet discovery
pub var has_signet_seeds: bool = false;

// ---------------------------------------------------------------------------
// Runtime initialization (call from main before anything else)
// ---------------------------------------------------------------------------

/// Initialize signet mode at runtime from --signet flag.
/// Must be called before any network operations.
pub fn initSignet(challenge_hex: []const u8) !void {
    magic = try computeSignetMagic(challenge_hex);
    default_port = 38333;
    is_signet = true;
    has_signet_seeds = false;
}

/// Initialize default (public) signet.
pub fn initSignetDefault() !void {
    try initSignet(default_signet_challenge_hex);
    has_signet_seeds = true;
}

pub const SignetParseResult = struct {
    cmd_arg: ?[]const u8,
    enabled: bool,
};

/// Parse leading --signet flag and initialize network settings.
/// Returns the command argument to use (if any).
pub fn parseSignetArgs(args_iter: anytype) !SignetParseResult {
    const first_arg = args_iter.next();
    if (first_arg) |arg| {
        if (std.mem.eql(u8, arg, "--signet")) {
            const maybe_next = args_iter.next();
            if (maybe_next) |next| {
                if (isCommandArg(next)) {
                    try initSignetDefault();
                    return .{ .cmd_arg = next, .enabled = true };
                }
                try initSignet(next);
                return .{ .cmd_arg = args_iter.next(), .enabled = true };
            }
            try initSignetDefault();
            return .{ .cmd_arg = args_iter.next(), .enabled = true };
        }
    }

    return .{ .cmd_arg = first_arg, .enabled = false };
}

/// Compute signet magic from challenge hex.
/// Algorithm: first 4 bytes of SHA256d(CompactSize(len) ++ challenge_bytes)
fn computeSignetMagic(challenge_hex: []const u8) !u32 {
    if (challenge_hex.len % 2 != 0) return error.InvalidHexLength;
    const challenge_len: u64 = challenge_hex.len / 2;

    // Encode CompactSize length prefix (varint)
    var prefix: [9]u8 = undefined;
    const prefix_len = encodeCompactSize(&prefix, challenge_len);

    // SHA256d (double SHA256) with streaming input
    var sha = std.crypto.hash.sha2.Sha256.init(.{});
    sha.update(prefix[0..prefix_len]);

    var i: usize = 0;
    var one: [1]u8 = undefined;
    while (i < challenge_hex.len) : (i += 2) {
        one[0] = std.fmt.parseInt(u8, challenge_hex[i..][0..2], 16) catch
            return error.InvalidHexChar;
        sha.update(one[0..1]);
    }

    var h1: [32]u8 = undefined;
    sha.final(&h1);

    var h2: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&h1, &h2, .{});

    return std.mem.readInt(u32, h2[0..4], .little);
}

fn encodeCompactSize(buf: *[9]u8, value: u64) usize {
    if (value < 0xfd) {
        buf[0] = @intCast(value);
        return 1;
    } else if (value <= 0xffff) {
        buf[0] = 0xfd;
        const v: u16 = @intCast(value);
        buf[1] = @intCast(v & 0xff);
        buf[2] = @intCast((v >> 8) & 0xff);
        return 3;
    } else if (value <= 0xffffffff) {
        buf[0] = 0xfe;
        const v: u32 = @intCast(value);
        buf[1] = @intCast(v & 0xff);
        buf[2] = @intCast((v >> 8) & 0xff);
        buf[3] = @intCast((v >> 16) & 0xff);
        buf[4] = @intCast((v >> 24) & 0xff);
        return 5;
    } else {
        buf[0] = 0xff;
        const v: u64 = value;
        buf[1] = @intCast(v & 0xff);
        buf[2] = @intCast((v >> 8) & 0xff);
        buf[3] = @intCast((v >> 16) & 0xff);
        buf[4] = @intCast((v >> 24) & 0xff);
        buf[5] = @intCast((v >> 32) & 0xff);
        buf[6] = @intCast((v >> 40) & 0xff);
        buf[7] = @intCast((v >> 48) & 0xff);
        buf[8] = @intCast((v >> 56) & 0xff);
        return 9;
    }
}

fn isCommandArg(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "broadcast") or
        std.mem.eql(u8, arg, "explore") or
        std.mem.eql(u8, arg, "help") or
        std.mem.eql(u8, arg, "--help") or
        std.mem.eql(u8, arg, "-h");
}

test "compute signet magic from BIP-325 example" {
    const challenge =
        "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be43051ae";
    const computed_magic = try computeSignetMagic(challenge);
    try std.testing.expectEqual(@as(u32, 0xA553C67E), computed_magic);
}
