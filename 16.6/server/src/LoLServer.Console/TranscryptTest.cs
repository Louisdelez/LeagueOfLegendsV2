using System;
using LoLServer.Core.Network;

namespace LoLServer.Console;

public static class TranscryptTest
{
    public static void Run()
    {
        var realKey = "jNdWPAc3Vb5AyjoYdkar/g==";
        var privateKey = "17BLOhi6KZsTtldTsizvHg==";

        var realCipher = BlowFish.FromBase64(realKey);
        var privateCipher = BlowFish.FromBase64(privateKey);

        // Real server VERIFY_CONNECT (111 bytes, frame 911)
        var realVerifyHex =
            "B2CC6CAA8092ADE003DC4263FDA135DA21CBDD3B0EB45076A328CB7BF8A0616D" +
            "2E4A28822D6385E3B2440080A1BA6C9ABD2077359378807A969AA3C42F4DEB7F" +
            "2E2F3FC54C9AE6E82328982B6F5A074EAF7CA425C590A0FA050DCCF9FB0A78DD" +
            "804D02D9964515BF9A074C4C069280";

        var realVerify = HexToBytes(realVerifyHex);
        System.Console.WriteLine($"Real VERIFY: {realVerify.Length} bytes");

        // Extract payload (bytes 8 to 108)
        var payload = new byte[101];
        Array.Copy(realVerify, 8, payload, 0, 101);

        // Method 1: Decrypt payload with real key (ECB), then re-encrypt with private key
        var decPayload = realCipher.Decrypt(payload);
        var reEncPayload = privateCipher.Encrypt(decPayload);

        System.Console.WriteLine($"\nDecrypted payload (first 32): {BitConverter.ToString(decPayload, 0, 32)}");
        System.Console.WriteLine($"Re-encrypted (first 32): {BitConverter.ToString(reEncPayload, 0, 32)}");

        // Check if decrypted payload looks like ENet VERIFY_CONNECT
        System.Console.WriteLine($"\nDecrypted @0 as ENet:");
        if (decPayload.Length >= 6)
        {
            ushort peerID = (ushort)(decPayload[0] | (decPayload[1] << 8));
            ushort sentTime = (ushort)(decPayload[2] | (decPayload[3] << 8));
            byte cmd = decPayload[4];
            byte ch = decPayload[5];
            System.Console.WriteLine($"  PeerID=0x{peerID:X4} Time=0x{sentTime:X4} Cmd=0x{cmd:X2} (type={cmd & 0x0F}) Ch=0x{ch:X2}");

            if ((cmd & 0x0F) == 3) // VERIFY_CONNECT
            {
                System.Console.WriteLine("  → VERIFY_CONNECT!");
                ushort seqNo = (ushort)(decPayload[6] | (decPayload[7] << 8));
                ushort outPeerID = (ushort)(decPayload[8] | (decPayload[9] << 8));
                uint mtu = BitConverter.ToUInt32(decPayload, 12);
                uint window = BitConverter.ToUInt32(decPayload, 16);
                uint channels = BitConverter.ToUInt32(decPayload, 20);
                System.Console.WriteLine($"  SeqNo={seqNo} OutPeerID=0x{outPeerID:X4} MTU={mtu} Window={window} Channels={channels}");
            }
        }

        // Build private server VERIFY using transcrypted payload
        var privateVerify = new byte[111];
        // SessionID (DEADBEEF)
        privateVerify[0] = 0xEF; privateVerify[1] = 0xBE;
        privateVerify[2] = 0xAD; privateVerify[3] = 0xDE;
        // Checksum = private Encrypt(zeros)[0:3]
        var privEncZeros = privateCipher.Encrypt(new byte[8]);
        privateVerify[4] = privEncZeros[0]; // F9
        privateVerify[5] = privEncZeros[1]; // ED
        privateVerify[6] = privEncZeros[2]; // 26
        // Nonce (same as real)
        privateVerify[7] = realVerify[7]; // E0
        // Re-encrypted payload
        Array.Copy(reEncPayload, 0, privateVerify, 8, Math.Min(101, reEncPayload.Length));
        // Footer
        privateVerify[109] = 0x01; // sequence
        privateVerify[110] = (byte)((privEncZeros[1] << 4) | (privEncZeros[0] >> 4)); // footer pattern

        System.Console.WriteLine($"\nPrivate VERIFY (111B): {BitConverter.ToString(privateVerify, 0, 20)}...");
        System.Console.WriteLine($"Full hex: {BitConverter.ToString(privateVerify).Replace("-","")}");

        // Method 2: Use decrypted payload as-is (no re-encryption)
        var plainVerify = new byte[111];
        Array.Copy(privateVerify, 0, plainVerify, 0, 8); // Same header
        Array.Copy(decPayload, 0, plainVerify, 8, Math.Min(101, decPayload.Length));
        plainVerify[109] = 0x01;
        plainVerify[110] = privateVerify[110];
        System.Console.WriteLine($"\nPlain VERIFY (no re-enc): {BitConverter.ToString(plainVerify, 0, 20)}...");
        System.Console.WriteLine($"Full hex: {BitConverter.ToString(plainVerify).Replace("-","")}");
    }

    static byte[] HexToBytes(string hex)
    {
        hex = hex.Replace("-", "").Replace(" ", "");
        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return bytes;
    }
}
