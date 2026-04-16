using System;
using LoLServer.Core.Network;

namespace LoLServer.Console;

/// <summary>
/// Test: decode real packets as LENet Season 12 format (big-endian).
/// Maybe the ENTIRE packet is Blowfish ECB encrypted and the "header" that looks
/// like sessionID is actually just what Encrypt produces for the ENet header.
///
/// OR: the header (8 bytes) is plaintext and bytes 8+ are encrypted.
///
/// Run with: dotnet run -- --lenet-decode
/// </summary>
public static class LENetDecoder
{
    public static void Run()
    {
        var realKey = "jNdWPAc3Vb5AyjoYdkar/g==";
        var privateKey = "17BLOhi6KZsTtldTsizvHg==";
        var realCipher = BlowFish.FromBase64(realKey);
        var privateCipher = BlowFish.FromBase64(privateKey);

        System.Console.WriteLine("=== LENet Season 12 Decoder ===\n");

        // What does a proper Season12 CONNECT look like in plaintext?
        // Header: [4B SessionID BE][2B PeerID|0x8000 BE][2B TimeSent BE]
        // Command: [1B flags|cmd][1B channelID][2B reliableSeqNo BE]
        // Connect body: [2B outPeerID BE][2B MTU BE][4B windowSize BE][4B channelCount BE]
        //               [4B inBW BE][4B outBW BE][4B throttleInterval BE][4B throttleAccel BE]
        //               [4B throttleDecel BE][4B sessionID BE]

        // Build a correct CONNECT plaintext
        var connect = new byte[48]; // 8 header + 4 cmd + 36 connect body
        int off = 0;
        // SessionID = 0 (client doesn't know server session yet)
        WriteBE32(connect, off, 0); off += 4;
        // PeerID = 0x8000 (PeerID=0 | TimeSent flag)
        WriteBE16(connect, off, 0x8000); off += 2;
        // TimeSent = 0
        WriteBE16(connect, off, 0); off += 2;
        // Command byte: CONNECT(2) | SENT_TIME flag(0x80) = 0x82
        connect[off++] = 0x82;
        // ChannelID = 0xFF
        connect[off++] = 0xFF;
        // ReliableSeqNo = 1
        WriteBE16(connect, off, 1); off += 2;
        // OutgoingPeerID = 0
        WriteBE16(connect, off, 0); off += 2;
        // MTU = 996
        WriteBE16(connect, off, 996); off += 2;
        // WindowSize = 32768
        WriteBE32(connect, off, 32768); off += 4;
        // ChannelCount = 32
        WriteBE32(connect, off, 32); off += 4;
        // IncomingBandwidth = 0
        WriteBE32(connect, off, 0); off += 4;
        // OutgoingBandwidth = 0
        WriteBE32(connect, off, 0); off += 4;
        // PacketThrottleInterval = 32 (or other)
        WriteBE32(connect, off, 32); off += 4;
        // PacketThrottleAcceleration = 2
        WriteBE32(connect, off, 2); off += 4;
        // PacketThrottleDeceleration = 2
        WriteBE32(connect, off, 2); off += 4;
        // SessionID = some value
        WriteBE32(connect, off, 0); off += 4;

        System.Console.WriteLine($"Plaintext CONNECT ({connect.Length}B): {Hex(connect)}");

        // Encrypt with private key
        var encConnect = privateCipher.Encrypt(connect);
        System.Console.WriteLine($"ECB Encrypted ({encConnect.Length}B): {Hex(encConnect)}");

        // Compare with actual private capture
        System.Console.WriteLine($"\nActual private capture first 48B:");
        System.Console.WriteLine($"  00-00-00-00-00-00-00-00-ED-E3-6B-43-F9-ED-26-xx...");
        System.Console.WriteLine($"  Encrypt(header 00000000 00000000) = {Hex(privateCipher.Encrypt(new byte[8]))}");
        System.Console.WriteLine($"  Our encrypted header             = {Hex(encConnect, 8)}");

        // If entire packet is ECB encrypted:
        // Encrypt(00000000 80000000) should give the first 8 bytes of captured private packet
        // But captured first 8 bytes are 00-00-00-00-00-00-00-00
        // Encrypt(anything) won't give zeros unless the plaintext is Decrypt(zeros)

        // So the header is NOT ECB encrypted → it's plaintext!
        System.Console.WriteLine($"\n=== Decrypt(zeros) = {Hex(privateCipher.Decrypt(new byte[8]))}");
        System.Console.WriteLine($"If header were ECB'd, plaintext would need to be Decrypt(zeros)");
        System.Console.WriteLine($"But we expect 00000000 (sessionID=0) as header → header is PLAINTEXT");

        // NOW: try Blowfish ECB on bytes 8+ of the REAL server packet
        // Frame 911: B2CC6CAA 8092ADE0 | 03DC4263FDA135DA...
        System.Console.WriteLine($"\n=== Decrypting bytes 8+ of real VERIFY (frame 911) ===");
        var realVerify = HexToBytes(
            "B2CC6CAA8092ADE003DC4263FDA135DA21CBDD3B0EB45076A328CB7BF8A0616D" +
            "2E4A28822D6385E3B2440080A1BA6C9ABD2077359378807A969AA3C42F4DEB7F" +
            "2E2F3FC54C9AE6E82328982B6F5A074EAF7CA425C590A0FA050DCCF9FB0A78DD" +
            "804D02D9964515BF9A074C4C069280");

        var verifyPayload = new byte[realVerify.Length - 8];
        Array.Copy(realVerify, 8, verifyPayload, 0, verifyPayload.Length);

        var decPayload = realCipher.Decrypt(verifyPayload);
        System.Console.WriteLine($"ECB Dec payload first 32: {Hex(decPayload, 32)}");

        // Parse as LENet Season 12 command (big-endian)
        if (decPayload.Length >= 4)
        {
            byte cmdByte = decPayload[0];
            byte channelId = decPayload[1];
            ushort seqNo = (ushort)((decPayload[2] << 8) | decPayload[3]);
            int cmd = cmdByte & 0x0F;
            System.Console.WriteLine($"  Cmd=0x{cmdByte:X2} (type={cmd}) Channel=0x{channelId:X2} SeqNo={seqNo}");

            if (cmd == 3) // VERIFY_CONNECT
            {
                System.Console.WriteLine($"  >>> VERIFY_CONNECT! <<<");
                if (decPayload.Length >= 4 + 36)
                {
                    ushort outPeerID = ReadBE16(decPayload, 4);
                    ushort mtu = ReadBE16(decPayload, 6);
                    uint winSize = ReadBE32(decPayload, 8);
                    uint chanCount = ReadBE32(decPayload, 12);
                    System.Console.WriteLine($"  OutPeerID={outPeerID} MTU={mtu} Window={winSize} Channels={chanCount}");
                }
            }
        }

        // Also try on the SECOND VERIFY (frame 915) which has a different nonce
        System.Console.WriteLine($"\n=== Frame 915 (second VERIFY) ===");
        var realVerify2 = HexToBytes(
            "B2CC6CAA8092AD0B214D47F9D8DC4AD7DBA243AA3A5EFDADCDBE092223947FC1" +
            "4191ABF891D361CA59E58AA3EAC3AD08E5E9AF43FCE91614EBD34820FE8AA9AF" +
            "8B88379AAE31BCF74553FAF3F98E99D419735D5AD6081C85B2A0C880D1796B50" +
            "676F25B8EBCCCF2BF9FD1344409280");
        var vp2 = new byte[realVerify2.Length - 8];
        Array.Copy(realVerify2, 8, vp2, 0, vp2.Length);
        var dec2 = realCipher.Decrypt(vp2);
        System.Console.WriteLine($"ECB Dec payload first 32: {Hex(dec2, 32)}");
        if (dec2.Length >= 4)
        {
            byte cmdByte = dec2[0];
            int cmd = cmdByte & 0x0F;
            System.Console.WriteLine($"  Cmd=0x{cmdByte:X2} (type={cmd}) Channel=0x{dec2[1]:X2}");
            if (cmd == 3)
                System.Console.WriteLine($"  >>> VERIFY_CONNECT! <<<");
        }

        // Check if the two VERIFY payloads decrypt to the same thing (they should if ECB)
        System.Console.WriteLine($"\n=== Comparison ===");
        System.Console.WriteLine($"VERIFY1 dec[0-7]: {Hex(decPayload, 8)}");
        System.Console.WriteLine($"VERIFY2 dec[0-7]: {Hex(dec2, 8)}");
        bool same = true;
        for (int i = 0; i < Math.Min(decPayload.Length, dec2.Length); i++)
            if (decPayload[i] != dec2[i]) { same = false; break; }
        System.Console.WriteLine($"Same plaintext: {same}");
        if (!same)
            System.Console.WriteLine($"→ Different plaintext with ECB = NOT ECB encryption (or TimeSent differs)");
    }

    static void WriteBE16(byte[] buf, int off, ushort val)
    {
        buf[off] = (byte)((val >> 8) & 0xFF);
        buf[off + 1] = (byte)(val & 0xFF);
    }

    static void WriteBE32(byte[] buf, int off, uint val)
    {
        buf[off] = (byte)((val >> 24) & 0xFF);
        buf[off + 1] = (byte)((val >> 16) & 0xFF);
        buf[off + 2] = (byte)((val >> 8) & 0xFF);
        buf[off + 3] = (byte)(val & 0xFF);
    }

    static ushort ReadBE16(byte[] buf, int off) => (ushort)((buf[off] << 8) | buf[off + 1]);
    static uint ReadBE32(byte[] buf, int off) => (uint)((buf[off] << 24) | (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3]);

    static string Hex(byte[] data, int maxLen = 64) => BitConverter.ToString(data, 0, Math.Min(maxLen, data.Length));

    static byte[] HexToBytes(string hex)
    {
        hex = hex.Replace("-", "").Replace(" ", "");
        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return bytes;
    }
}
