using System;
using System.IO;
using LoLServer.Core.Network;

namespace LoLServer.Console;

/// <summary>
/// Test Blowfish CBC decryption on captured packets.
/// The client might use CBC instead of ECB for transport encryption.
/// Run with: dotnet run -- --cbc-test
/// </summary>
public static class CbcDecryptTest
{
    public static void Run(string blowfishKey = "17BLOhi6KZsTtldTsizvHg==")
    {
        var cipher = BlowFish.FromBase64(blowfishKey);

        var captureDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs", "raw_capture");
        if (!Directory.Exists(captureDir))
        {
            System.Console.WriteLine($"No captures at {captureDir}");
            return;
        }

        var file = Directory.GetFiles(captureDir, "*.bin")[0];
        var data = File.ReadAllBytes(file);
        System.Console.WriteLine($"File: {Path.GetFileName(file)} ({data.Length}B)");
        System.Console.WriteLine($"Raw first 32: {BitConverter.ToString(data, 0, 32)}");
        System.Console.WriteLine();

        // ECB decrypt for reference
        var ecbDec = cipher.Decrypt(data);
        System.Console.WriteLine($"ECB Decrypt first 32: {BitConverter.ToString(ecbDec, 0, 32)}");

        // CBC decrypt with various IVs
        System.Console.WriteLine();
        System.Console.WriteLine("=== CBC Decrypt tests ===");

        // IV = all zeros (common default)
        TestCbc(cipher, data, new byte[8], "IV=zeros");

        // IV = first 8 bytes of data (the zeros)
        TestCbc(cipher, data, new byte[8], "IV=first8(zeros)");

        // IV = the Blowfish key bytes (first 8)
        var keyBytes = Convert.FromBase64String(blowfishKey);
        var keyIv = new byte[8];
        Array.Copy(keyBytes, keyIv, Math.Min(8, keyBytes.Length));
        TestCbc(cipher, data, keyIv, $"IV=key({BitConverter.ToString(keyIv)})");

        // CBC on data starting at offset 8 (skip checksum)
        System.Console.WriteLine();
        System.Console.WriteLine("=== CBC on bytes 8+ (skip 8-byte checksum) ===");
        var dataFrom8 = new byte[data.Length - 8];
        Array.Copy(data, 8, dataFrom8, 0, dataFrom8.Length);

        TestCbc(cipher, dataFrom8, new byte[8], "Offset8+IV=zeros");

        // IV = the 8 zero bytes from the original packet
        TestCbc(cipher, dataFrom8, new byte[8], "Offset8+IV=zeros");

        // IV = ECB decrypt of the zero block (82-BC-62-33-73-11-01-C4)
        TestCbc(cipher, dataFrom8, ecbDec.AsSpan(0, 8).ToArray(), $"Offset8+IV=ECBdec0({BitConverter.ToString(ecbDec, 0, 8)})");

        // Try CFB and OFB modes manually
        System.Console.WriteLine();
        System.Console.WriteLine("=== OFB mode (keystream XOR) ===");
        TestOfb(cipher, data, new byte[8], "Full+IV=zeros");
        TestOfb(cipher, dataFrom8, new byte[8], "From8+IV=zeros");

        // Try: the 7 constant bytes + counter byte as IV for data from offset 16
        System.Console.WriteLine();
        System.Console.WriteLine("=== Data from offset 16 with header as IV ===");
        if (data.Length > 16)
        {
            var dataFrom16 = new byte[data.Length - 16];
            Array.Copy(data, 16, dataFrom16, 0, dataFrom16.Length);
            var headerIv = new byte[8];
            Array.Copy(data, 8, headerIv, 0, 8); // bytes 8-15 as IV

            TestCbc(cipher, dataFrom16, headerIv, "From16+IV=header");
            TestOfb(cipher, dataFrom16, headerIv, "From16+IV=header(OFB)");

            // ECB decrypt of bytes 16+
            var ecbFrom16 = cipher.Decrypt(dataFrom16);
            System.Console.WriteLine($"ECB from16: {BitConverter.ToString(ecbFrom16, 0, Math.Min(32, ecbFrom16.Length))}");

            // Check for ENet patterns
            for (int off = 0; off <= 8; off += 2)
            {
                if (off + 5 < ecbFrom16.Length)
                {
                    byte cmd = (byte)(ecbFrom16[off + 4] & 0x0F);
                    if (cmd >= 1 && cmd <= 12)
                    {
                        ushort pid = (ushort)(ecbFrom16[off] | (ecbFrom16[off + 1] << 8));
                        System.Console.WriteLine($"  ECB@16+{off}: PeerID=0x{pid:X4} Cmd={cmd}");
                    }
                }
            }
        }
    }

    static void TestCbc(BlowFish cipher, byte[] data, byte[] iv, string label)
    {
        var result = BlowfishCbc(cipher, data, iv, decrypt: true);
        System.Console.Write($"  CBC({label}): {BitConverter.ToString(result, 0, Math.Min(24, result.Length))}");

        // Check if result looks like ENet
        CheckENet(result);
        System.Console.WriteLine();
    }

    static void TestOfb(BlowFish cipher, byte[] data, byte[] iv, string label)
    {
        var result = BlowfishOfb(cipher, data, iv);
        System.Console.Write($"  OFB({label}): {BitConverter.ToString(result, 0, Math.Min(24, result.Length))}");
        CheckENet(result);
        System.Console.WriteLine();
    }

    static void CheckENet(byte[] data)
    {
        // Check for ENet CONNECT command (0x82 = cmd 2 | SENT_TIME)
        for (int off = 0; off <= 4; off++)
        {
            if (off < data.Length && (data[off] == 0x82 || data[off] == 0x02))
            {
                System.Console.Write($" ← CONNECT? @{off}");
            }
        }
        // Check Season 8 format: [sessionID][peerID|flags][sentTime:2][cmd]
        if (data.Length >= 5)
        {
            byte sess = data[0];
            byte peer = (byte)(data[1] & 0x7F);
            bool sentTime = (data[1] & 0x80) != 0;
            if (peer == 0x7F || peer == 0xFF)
            {
                System.Console.Write($" ← S8 header? sess={sess} peer=0x{peer:X2}");
            }
        }
    }

    /// <summary>
    /// Blowfish CBC decrypt: each plaintext block = Decrypt(ciphertext) XOR previous_ciphertext
    /// </summary>
    static byte[] BlowfishCbc(BlowFish cipher, byte[] data, byte[] iv, bool decrypt)
    {
        var result = new byte[data.Length];
        var prevBlock = (byte[])iv.Clone();

        int blocks = data.Length / 8;
        for (int i = 0; i < blocks; i++)
        {
            var block = new byte[8];
            Array.Copy(data, i * 8, block, 0, 8);

            byte[] processed;
            if (decrypt)
            {
                processed = cipher.Decrypt(block);
                for (int j = 0; j < 8; j++)
                    result[i * 8 + j] = (byte)(processed[j] ^ prevBlock[j]);
                Array.Copy(block, prevBlock, 8); // prev = ciphertext
            }
            else
            {
                for (int j = 0; j < 8; j++)
                    block[j] ^= prevBlock[j];
                processed = cipher.Encrypt(block);
                Array.Copy(processed, 0, result, i * 8, 8);
                Array.Copy(processed, prevBlock, 8);
            }
        }
        // Copy remaining bytes
        int rem = data.Length % 8;
        if (rem > 0) Array.Copy(data, blocks * 8, result, blocks * 8, rem);

        return result;
    }

    /// <summary>
    /// Blowfish OFB: keystream = Encrypt(Encrypt(Encrypt(IV)))..., plaintext = data XOR keystream
    /// </summary>
    static byte[] BlowfishOfb(BlowFish cipher, byte[] data, byte[] iv)
    {
        var result = new byte[data.Length];
        var feedback = (byte[])iv.Clone();

        int blocks = data.Length / 8;
        for (int i = 0; i < blocks; i++)
        {
            feedback = cipher.Encrypt(feedback);
            for (int j = 0; j < 8; j++)
                result[i * 8 + j] = (byte)(data[i * 8 + j] ^ feedback[j]);
        }
        int rem = data.Length % 8;
        if (rem > 0)
        {
            feedback = cipher.Encrypt(feedback);
            for (int j = 0; j < rem; j++)
                result[blocks * 8 + j] = (byte)(data[blocks * 8 + j] ^ feedback[j]);
        }

        return result;
    }
}
