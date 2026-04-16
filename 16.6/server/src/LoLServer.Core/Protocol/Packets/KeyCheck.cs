using System;

namespace LoLServer.Core.Protocol.Packets;

/// <summary>
/// KeyCheck packet - the FIRST packet exchanged on CHL_HANDSHAKE (channel 0).
/// This is NEVER encrypted (handshake channel is exempt from Blowfish).
///
/// Structure (32 bytes):
/// [1B action][3B pad][4B clientID][8B playerID][4B versionNo][8B checksum][4B pad]
///
/// The checksum field contains the playerID encrypted with that player's Blowfish key.
/// Server decrypts checksum, verifies it matches playerID, then responds.
/// </summary>
public class KeyCheck
{
    public const int PacketSize = 32;

    public byte Action { get; set; }
    public ushort ClientId { get; set; }
    public ulong PlayerId { get; set; }
    public uint VersionNo { get; set; }
    public ulong CheckSum { get; set; }

    public static KeyCheck Deserialize(byte[] data)
    {
        if (data.Length < PacketSize)
            throw new ArgumentException($"KeyCheck packet must be at least {PacketSize} bytes, got {data.Length}");

        return new KeyCheck
        {
            Action = data[0],
            // 3 bytes padding (1-3)
            ClientId = BitConverter.ToUInt16(data, 4),
            PlayerId = BitConverter.ToUInt64(data, 8),
            VersionNo = BitConverter.ToUInt32(data, 16),
            CheckSum = BitConverter.ToUInt64(data, 20),
            // 4 bytes padding (28-31)
        };
    }

    public byte[] Serialize()
    {
        var data = new byte[PacketSize];

        data[0] = Action;
        // 3 bytes padding (1-3) = 0
        BitConverter.GetBytes(ClientId).CopyTo(data, 4);
        BitConverter.GetBytes(PlayerId).CopyTo(data, 8);
        BitConverter.GetBytes(VersionNo).CopyTo(data, 16);
        BitConverter.GetBytes(CheckSum).CopyTo(data, 20);
        // 4 bytes padding (28-31) = 0

        return data;
    }

    /// <summary>
    /// Verify the KeyCheck by decrypting the checksum and comparing to playerID.
    /// </summary>
    public bool Verify(Network.BlowFish blowfish)
    {
        var checksumBytes = BitConverter.GetBytes(CheckSum);
        var decrypted = blowfish.DecryptBlock(checksumBytes);
        var decryptedPlayerId = BitConverter.ToUInt64(decrypted, 0);
        return decryptedPlayerId == PlayerId;
    }

    /// <summary>
    /// Create a KeyCheck response with the checksum properly encrypted.
    /// </summary>
    public static KeyCheck CreateResponse(ushort clientId, ulong playerId, Network.BlowFish blowfish)
    {
        var playerIdBytes = BitConverter.GetBytes(playerId);
        var encrypted = blowfish.EncryptBlock(playerIdBytes);
        var checksum = BitConverter.ToUInt64(encrypted, 0);

        return new KeyCheck
        {
            Action = 0,
            ClientId = clientId,
            PlayerId = playerId,
            VersionNo = 0,
            CheckSum = checksum
        };
    }

    public override string ToString()
    {
        return $"KeyCheck(Action={Action}, ClientId={ClientId}, PlayerId={PlayerId}, Version={VersionNo}, CheckSum=0x{CheckSum:X16})";
    }
}
