using System;
using System.IO;
using LoLServer.Core.Network;

namespace LoLServer.Console;

/// <summary>
/// Quick test to see if captured 519B packets can be Blowfish-decrypted into ENet.
/// Run with: dotnet run -- --decrypt-test
/// </summary>
public static class DecryptTest
{
    public static void Run(string blowfishKey = "17BLOhi6KZsTtldTsizvHg==")
    {
        var cipher = BlowFish.FromBase64(blowfishKey);

        var captureDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs", "raw_capture");
        if (!Directory.Exists(captureDir))
        {
            System.Console.WriteLine($"[ERROR] No raw capture directory at {captureDir}");
            return;
        }

        var files = Directory.GetFiles(captureDir, "*.bin");
        System.Console.WriteLine($"Found {files.Length} capture files in {captureDir}");
        System.Console.WriteLine();

        // Test first 5 files
        int tested = 0;
        foreach (var file in files)
        {
            if (tested++ >= 5) break;

            var data = File.ReadAllBytes(file);
            System.Console.WriteLine($"=== {Path.GetFileName(file)} ({data.Length}B) ===");
            System.Console.WriteLine($"  Raw 0-15: {BitConverter.ToString(data, 0, Math.Min(16, data.Length))}");

            // Strategy 1: Blowfish decrypt after 8-byte header
            TestDecrypt(cipher, data, 8, "Blowfish @8");

            // Strategy 2: Blowfish decrypt full packet
            TestDecrypt(cipher, data, 0, "Blowfish @0");

            // Strategy 3: XOR with key then check
            // Strategy 4: Just check raw bytes as ENet at various offsets
            for (int off = 0; off <= 16; off += 2)
            {
                if (off + 4 >= data.Length) continue;
                byte cmdByte = data[off + 4];
                int cmd = cmdByte & 0x0F;
                if (cmd >= 1 && cmd <= 12)
                {
                    ushort pid = (ushort)(data[off] | (data[off + 1] << 8));
                    System.Console.WriteLine($"  [RAW @{off}] PeerID=0x{pid:X4} Cmd={cmd} (0x{cmdByte:X2}) ← possible ENet");
                }
            }

            System.Console.WriteLine();
        }
    }

    private static void TestDecrypt(BlowFish cipher, byte[] data, int offset, string label)
    {
        if (offset >= data.Length) return;

        var encrypted = new byte[data.Length - offset];
        Array.Copy(data, offset, encrypted, 0, encrypted.Length);

        try
        {
            var decrypted = cipher.Decrypt(encrypted);
            System.Console.Write($"  [{label}] First 16: {BitConverter.ToString(decrypted, 0, Math.Min(16, decrypted.Length))}");

            // Check if result looks like ENet
            if (decrypted.Length >= 5)
            {
                ushort peerID = (ushort)(decrypted[0] | (decrypted[1] << 8));
                byte cmdByte = decrypted[4];
                int cmd = cmdByte & 0x0F;

                if (cmd >= 1 && cmd <= 12)
                {
                    System.Console.Write($" → ENet! PeerID=0x{peerID:X4} Cmd={cmd}");
                    if (cmd == 2) System.Console.Write(" (CONNECT)");
                    if (cmd == 6) System.Console.Write(" (RELIABLE)");
                }
                else
                {
                    System.Console.Write($" → Not ENet (cmd=0x{cmdByte:X2})");
                }
            }
            System.Console.WriteLine();
        }
        catch (Exception ex)
        {
            System.Console.WriteLine($"  [{label}] Failed: {ex.Message}");
        }
    }
}
