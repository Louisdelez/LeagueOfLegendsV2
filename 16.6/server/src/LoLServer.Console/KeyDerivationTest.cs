using System;
using LoLServer.Core.Network;

namespace LoLServer.Console;

/// <summary>
/// Test various Blowfish encrypt/decrypt operations to find what produces
/// the constant bytes ED-E3-6B-43-F9-ED-26 seen in the 519B packets.
/// Run with: dotnet run -- --key-test
/// </summary>
public static class KeyDerivationTest
{
    public static void Run(string blowfishKey = "17BLOhi6KZsTtldTsizvHg==")
    {
        var cipher = BlowFish.FromBase64(blowfishKey);
        var target = new byte[] { 0xED, 0xE3, 0x6B, 0x43, 0xF9, 0xED, 0x26 };

        System.Console.WriteLine($"Blowfish Key: {blowfishKey}");
        System.Console.WriteLine($"Target: {BitConverter.ToString(target)}");
        System.Console.WriteLine();

        // Test 1: Encrypt various 8-byte plaintexts and check if first 7 bytes match
        var testPlaintexts = new (string name, byte[] data)[]
        {
            ("all zeros", new byte[8]),
            ("all FF", new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }),
            ("CONNECT header (FF FF 00 00 82 FF 01 00)", new byte[] { 0xFF, 0xFF, 0x00, 0x00, 0x82, 0xFF, 0x01, 0x00 }),
            ("Session8 (00 FF 00 00 82 FF 01 00)", new byte[] { 0x00, 0xFF, 0x00, 0x00, 0x82, 0xFF, 0x01, 0x00 }),
            ("Session8 (00 7F 00 00 82 FF 01 00)", new byte[] { 0x00, 0x7F, 0x00, 0x00, 0x82, 0xFF, 0x01, 0x00 }),
            ("PeerID 7F (7F 00 00 00 00 00 00 00)", new byte[] { 0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }),
            ("ConnectID=0 ENet header", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00 }),
            // Season 8 header format: [sessionID][peerID|flags][sentTime:2]
            ("S8: sess=0 peer=FF time=0", new byte[] { 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }),
            ("S8: sess=0 peer=7F time=0", new byte[] { 0x00, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }),
            ("S8: sess=0 peer=FF|ST time=0", new byte[] { 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }),
            // ENet CONNECT command byte patterns
            ("ENet CONNECT cmd", new byte[] { 0x82, 0xFF, 0x00, 0x01, 0xFF, 0xFF, 0x00, 0x00 }),
            ("ENet CONNECT no flag", new byte[] { 0x02, 0xFF, 0x00, 0x01, 0xFF, 0xFF, 0x00, 0x00 }),
        };

        System.Console.WriteLine("=== Encrypt tests (does Encrypt(X) == target?) ===");
        foreach (var (name, data) in testPlaintexts)
        {
            var encrypted = cipher.Encrypt(data);
            bool match7 = true;
            for (int i = 0; i < 7 && i < encrypted.Length; i++)
                if (encrypted[i] != target[i]) { match7 = false; break; }

            var marker = match7 ? " <<<< MATCH!" : "";
            System.Console.WriteLine($"  Enc({name}):");
            System.Console.WriteLine($"    = {BitConverter.ToString(encrypted)}{marker}");
        }

        System.Console.WriteLine();
        System.Console.WriteLine("=== Decrypt tests (does Decrypt(target+XX) make sense?) ===");
        // Try decrypting the target bytes (with byte 8 = 0x00 through 0x05)
        for (byte lastByte = 0; lastByte < 6; lastByte++)
        {
            var block = new byte[8];
            Array.Copy(target, block, 7);
            block[7] = lastByte;
            var decrypted = cipher.Decrypt(block);
            System.Console.WriteLine($"  Dec(target+0x{lastByte:X2}) = {BitConverter.ToString(decrypted)}");
        }

        // Also try Decrypt with actual captured byte 15 values
        System.Console.WriteLine();
        System.Console.WriteLine("=== Decrypt with actual byte 15 values from captures ===");
        foreach (byte b15 in new byte[] { 0x1B, 0xEB, 0xFE, 0x6F, 0xFD })
        {
            var block = new byte[8];
            Array.Copy(target, block, 7);
            block[7] = b15;
            var decrypted = cipher.Decrypt(block);
            var enc = cipher.Encrypt(block);
            System.Console.WriteLine($"  byte15=0x{b15:X2}: Dec={BitConverter.ToString(decrypted)} Enc={BitConverter.ToString(enc)}");
        }

        // Test: what if the ENTIRE 519 bytes are Blowfish-Encrypted (not decrypted)?
        // i.e., the client uses Encrypt to SCRAMBLE the data
        System.Console.WriteLine();
        System.Console.WriteLine("=== What plaintext Encrypts to all-zeros (first block)? ===");
        // If Encrypt(X) = 00-00-00-00-00-00-00-00, then X = Decrypt(00-00-00-00-00-00-00-00)
        var zeroBlock = new byte[8];
        var whatMakesZeros = cipher.Decrypt(zeroBlock);
        System.Console.WriteLine($"  Decrypt(00..00) = {BitConverter.ToString(whatMakesZeros)}");
        System.Console.WriteLine($"  Verify: Encrypt(above) = {BitConverter.ToString(cipher.Encrypt(whatMakesZeros))}");

        // And what encrypts to the target header?
        System.Console.WriteLine();
        System.Console.WriteLine("=== What plaintext Encrypts to target header? ===");
        for (byte b = 0; b < 5; b++)
        {
            var headerBlock = new byte[8];
            Array.Copy(target, headerBlock, 7);
            headerBlock[7] = b;
            var plain = cipher.Decrypt(headerBlock);
            System.Console.WriteLine($"  Decrypt(ED-E3-...-26-{b:X2}) = {BitConverter.ToString(plain)}");
        }
    }
}
