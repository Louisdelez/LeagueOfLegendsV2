using System;
using LoLServer.Core.Network;

namespace LoLServer.Console;

/// <summary>
/// Test all possible Blowfish encryption modes to decode the real server's VERIFY payload.
/// Run with: dotnet run -- --crypto-test
/// </summary>
public static class CryptoModeTest
{
    public static void Run()
    {
        var realKey = "jNdWPAc3Vb5AyjoYdkar/g==";
        var cipher = BlowFish.FromBase64(realKey);
        var encZeros = cipher.Encrypt(new byte[8]);

        System.Console.WriteLine($"Key: {realKey}");
        System.Console.WriteLine($"Encrypt(zeros): {Hex(encZeros)}");

        // Frame 911: Server VERIFY_CONNECT (111 bytes)
        // Header: B2CC6CAA 8092AD E0
        // Payload: bytes 8-108 (101 bytes)
        // Footer: bytes 109-110 (9280)
        var fullPacket = HexToBytes(
            "B2CC6CAA8092ADE003DC4263FDA135DA21CBDD3B0EB45076A328CB7BF8A0616D" +
            "2E4A28822D6385E3B2440080A1BA6C9ABD2077359378807A969AA3C42F4DEB7F" +
            "2E2F3FC54C9AE6E82328982B6F5A074EAF7CA425C590A0FA050DCCF9FB0A78DD" +
            "804D02D9964515BF9A074C4C069280");

        var payload = new byte[101];
        Array.Copy(fullPacket, 8, payload, 0, 101);
        byte nonce = fullPacket[7]; // E0

        System.Console.WriteLine($"Nonce: 0x{nonce:X2}");
        System.Console.WriteLine($"Payload first 16: {Hex(payload, 16)}");
        System.Console.WriteLine();

        // === TEST 1: ECB decrypt ===
        {
            var dec = cipher.Decrypt(payload);
            System.Console.WriteLine($"[ECB Decrypt] {Hex(dec, 16)}");
            CheckENet(dec, "ECB");
        }

        // === TEST 2: ECB encrypt (reverse) ===
        {
            var enc = cipher.Encrypt(payload);
            System.Console.WriteLine($"[ECB Encrypt] {Hex(enc, 16)}");
            CheckENet(enc, "ECB-Rev");
        }

        // === TEST 3: OFB mode with various IVs ===
        var ivTests = new (string name, byte[] iv)[] {
            ("zeros", new byte[8]),
            ("encZeros", encZeros),
            ("checksum+nonce", new byte[] { 0x80, 0x92, 0xAD, 0xE0, 0x00, 0x00, 0x00, 0x00 }),
            ("nonce+checksum", new byte[] { 0xE0, 0x80, 0x92, 0xAD, 0x00, 0x00, 0x00, 0x00 }),
            ("checksum+nonce+pad", new byte[] { 0x80, 0x92, 0xAD, 0xE0, 0x80, 0x92, 0xAD, 0xE0 }),
            ("sessionID", new byte[] { 0xB2, 0xCC, 0x6C, 0xAA, 0x00, 0x00, 0x00, 0x00 }),
            ("sessionID+nonce", new byte[] { 0xB2, 0xCC, 0x6C, 0xAA, 0xE0, 0x00, 0x00, 0x00 }),
            ("header4-7", new byte[] { 0x80, 0x92, 0xAD, 0xE0, 0x03, 0xDC, 0x42, 0x63 }),
            ("nonce_repeat", new byte[] { 0xE0, 0xE0, 0xE0, 0xE0, 0xE0, 0xE0, 0xE0, 0xE0 }),
            ("encZeros_xor_nonce", XorByte(encZeros, nonce)),
        };

        System.Console.WriteLine("\n=== OFB Mode Tests ===");
        foreach (var (name, iv) in ivTests)
        {
            var dec = BlowfishOfb(cipher, payload, iv);
            System.Console.Write($"[OFB iv={name}] {Hex(dec, 16)}");
            if (CheckENet(dec, "")) System.Console.Write(" <<<");
            System.Console.WriteLine();
        }

        System.Console.WriteLine("\n=== CBC Mode Tests ===");
        foreach (var (name, iv) in ivTests)
        {
            var dec = BlowfishCbc(cipher, payload, iv);
            System.Console.Write($"[CBC iv={name}] {Hex(dec, 16)}");
            if (CheckENet(dec, "")) System.Console.Write(" <<<");
            System.Console.WriteLine();
        }

        System.Console.WriteLine("\n=== CFB Mode Tests ===");
        foreach (var (name, iv) in ivTests)
        {
            var dec = BlowfishCfb(cipher, payload, iv);
            System.Console.Write($"[CFB iv={name}] {Hex(dec, 16)}");
            if (CheckENet(dec, "")) System.Console.Write(" <<<");
            System.Console.WriteLine();
        }

        // === TEST: XOR with Encrypt(counter) where counter starts at nonce ===
        System.Console.WriteLine("\n=== CTR Mode Tests ===");
        for (int startCounter = 0; startCounter < 4; startCounter++)
        {
            var dec = BlowfishCtr(cipher, payload, nonce, startCounter);
            System.Console.Write($"[CTR nonce=0x{nonce:X2} start={startCounter}] {Hex(dec, 16)}");
            if (CheckENet(dec, "")) System.Console.Write(" <<<");
            System.Console.WriteLine();
        }

        // === TEST: CBC with key-derived IVs ===
        System.Console.WriteLine("\n=== CBC with key-derived IVs ===");
        {
            // The real key raw bytes
            var keyBytes = Convert.FromBase64String("jNdWPAc3Vb5AyjoYdkar/g==");
            var ivFromKey = new byte[8];
            Array.Copy(keyBytes, 0, ivFromKey, 0, 8);

            var keyIvTests = new (string name, byte[] iv)[] {
                ("key[0:8]", ivFromKey),
                ("key[8:16]", new byte[] { keyBytes[8], keyBytes[9], keyBytes[10], keyBytes[11], keyBytes[12], keyBytes[13], keyBytes[14], keyBytes[15] }),
                ("encZeros_as_IV", encZeros),
                ("header[0:8]_of_packet", new byte[] { 0xB2, 0xCC, 0x6C, 0xAA, 0x80, 0x92, 0xAD, 0xE0 }),
                ("sessionID_padded", new byte[] { 0xB2, 0xCC, 0x6C, 0xAA, 0x00, 0x00, 0x00, 0x00 }),
                ("all_zeros", new byte[8]),
                ("all_FF", new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }),
                ("Decrypt(key[0:8])", cipher.Decrypt(ivFromKey)),
                ("Encrypt(key[0:8])", cipher.Encrypt(ivFromKey)),
            };

            foreach (var (name, iv) in keyIvTests)
            {
                var dec = BlowfishCbc(cipher, payload, iv);
                bool valid = false;
                if (dec.Length >= 6)
                {
                    int cmd = dec[4] & 0x0F;
                    if (cmd >= 1 && cmd <= 7) valid = true;
                    // Also check big-endian: cmd at byte 0
                    int cmd0 = dec[0] & 0x0F;
                    if (cmd0 >= 1 && cmd0 <= 7) valid = true;
                }
                var marker = valid ? " <<<" : "";
                System.Console.WriteLine($"[CBC iv={name}] {Hex(dec, 16)}{marker}");
                if (valid)
                {
                    // Parse as ENet
                    System.Console.WriteLine($"  @0: cmd=0x{dec[0]:X2}({dec[0]&0xF}) ch=0x{dec[1]:X2}");
                    System.Console.WriteLine($"  @4: cmd=0x{dec[4]:X2}({dec[4]&0xF}) ch=0x{dec[5]:X2}");
                }
            }

            // Also test: what if the IV is the nonce byte repeated 8 times?
            var nonceIv = new byte[] { nonce, nonce, nonce, nonce, nonce, nonce, nonce, nonce };
            {
                var dec = BlowfishCbc(cipher, payload, nonceIv);
                bool valid = (dec.Length >= 6 && (dec[0] & 0x0F) >= 1 && (dec[0] & 0x0F) <= 7);
                System.Console.WriteLine($"[CBC iv=nonce*8(0x{nonce:X2})] {Hex(dec, 16)}{(valid ? " <<<" : "")}");
            }

            // Test: what if the IV changes per-packet and is the concatenation of
            // checksum bytes or the Blowfish-encrypted session+nonce?
            var sessNonce = new byte[] { 0xB2, 0xCC, 0x6C, 0xAA, 0xE0, 0x00, 0x00, 0x00 };
            {
                var iv = cipher.Encrypt(sessNonce);
                var dec = BlowfishCbc(cipher, payload, iv);
                bool valid = (dec.Length >= 6 && (dec[0] & 0x0F) >= 1 && (dec[0] & 0x0F) <= 7);
                System.Console.WriteLine($"[CBC iv=Enc(sess+nonce)] {Hex(dec, 16)}{(valid ? " <<<" : "")}");
            }
        }

        // === TEST: Maybe the entire packet (including header) is the IV ===
        System.Console.WriteLine("\n=== Full header as IV ===");
        {
            var iv = new byte[8];
            Array.Copy(fullPacket, 0, iv, 0, 8); // B2CC6CAA 8092ADE0
            var dec = BlowfishOfb(cipher, payload, iv);
            System.Console.Write($"[OFB iv=header0-7] {Hex(dec, 16)}");
            if (CheckENet(dec, "")) System.Console.Write(" <<<");
            System.Console.WriteLine();

            dec = BlowfishCbc(cipher, payload, iv);
            System.Console.Write($"[CBC iv=header0-7] {Hex(dec, 16)}");
            if (CheckENet(dec, "")) System.Console.Write(" <<<");
            System.Console.WriteLine();

            dec = BlowfishCfb(cipher, payload, iv);
            System.Console.Write($"[CFB iv=header0-7] {Hex(dec, 16)}");
            if (CheckENet(dec, "")) System.Console.Write(" <<<");
            System.Console.WriteLine();
        }
    }

    static byte[] BlowfishOfb(BlowFish cipher, byte[] data, byte[] iv)
    {
        var result = new byte[data.Length];
        var feedback = (byte[])iv.Clone();
        for (int i = 0; i < data.Length; i += 8)
        {
            feedback = cipher.Encrypt(feedback);
            int blockLen = Math.Min(8, data.Length - i);
            for (int j = 0; j < blockLen; j++)
                result[i + j] = (byte)(data[i + j] ^ feedback[j]);
        }
        return result;
    }

    static byte[] BlowfishCbc(BlowFish cipher, byte[] data, byte[] iv)
    {
        var result = new byte[data.Length];
        var prevBlock = (byte[])iv.Clone();
        for (int i = 0; i < data.Length - 7; i += 8)
        {
            var block = new byte[8];
            Array.Copy(data, i, block, 0, 8);
            var dec = cipher.Decrypt(block);
            for (int j = 0; j < 8; j++)
                result[i + j] = (byte)(dec[j] ^ prevBlock[j]);
            prevBlock = block;
        }
        // Handle trailing bytes
        int remaining = data.Length % 8;
        if (remaining > 0)
        {
            int offset = data.Length - remaining;
            Array.Copy(data, offset, result, offset, remaining);
        }
        return result;
    }

    static byte[] BlowfishCfb(BlowFish cipher, byte[] data, byte[] iv)
    {
        var result = new byte[data.Length];
        var feedback = (byte[])iv.Clone();
        for (int i = 0; i < data.Length; i += 8)
        {
            var keystream = cipher.Encrypt(feedback);
            int blockLen = Math.Min(8, data.Length - i);
            for (int j = 0; j < blockLen; j++)
                result[i + j] = (byte)(data[i + j] ^ keystream[j]);
            // In CFB, feedback = ciphertext block
            Array.Copy(data, i, feedback, 0, Math.Min(8, data.Length - i));
        }
        return result;
    }

    static byte[] BlowfishCtr(BlowFish cipher, byte[] data, byte nonce, int startCounter)
    {
        var result = new byte[data.Length];
        for (int i = 0; i < data.Length; i += 8)
        {
            var counter = new byte[8];
            counter[0] = nonce;
            int ctr = startCounter + (i / 8);
            counter[4] = (byte)(ctr & 0xFF);
            counter[5] = (byte)((ctr >> 8) & 0xFF);
            counter[6] = (byte)((ctr >> 16) & 0xFF);
            counter[7] = (byte)((ctr >> 24) & 0xFF);

            var keystream = cipher.Encrypt(counter);
            int blockLen = Math.Min(8, data.Length - i);
            for (int j = 0; j < blockLen; j++)
                result[i + j] = (byte)(data[i + j] ^ keystream[j]);
        }
        return result;
    }

    static byte[] XorByte(byte[] data, byte val)
    {
        var result = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
            result[i] = (byte)(data[i] ^ val);
        return result;
    }

    static bool CheckENet(byte[] data, string label)
    {
        if (data.Length < 6) return false;
        byte cmd = (byte)(data[4] & 0x0F);
        byte ch = data[5];
        // VERIFY_CONNECT = cmd 3, channel 0xFF
        if (cmd == 3 && ch == 0xFF)
        {
            if (label.Length > 0)
                System.Console.WriteLine($" → VERIFY_CONNECT! PeerID=0x{data[0] | (data[1] << 8):X4}");
            return true;
        }
        // CONNECT = cmd 2, channel 0xFF
        if (cmd == 2 && ch == 0xFF)
        {
            if (label.Length > 0)
                System.Console.WriteLine($" → CONNECT!");
            return true;
        }
        // Any valid ENet command
        if (cmd >= 1 && cmd <= 7)
            return true;
        return false;
    }

    static string Hex(byte[] data, int maxLen = 16, int offset = 0)
    {
        int len = Math.Min(maxLen, data.Length - offset);
        if (len <= 0) return "(empty)";
        return BitConverter.ToString(data, offset, len);
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
