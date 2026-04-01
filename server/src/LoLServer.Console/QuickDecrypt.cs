using System;
using System.IO;
using LoLServer.Core.Network;

namespace LoLServer.Console;

public static class QuickDecrypt
{
    public static void Run()
    {
        var cipher = BlowFish.FromBase64("17BLOhi6KZsTtldTsizvHg==");
        var logDir = @"D:\LeagueOfLegendsV2\client-private\Game\nethook_logs";

        // Find all SEND packets
        foreach (var f in Directory.GetFiles(logDir, "SEND_*.bin"))
        {
            var data = File.ReadAllBytes(f);
            var name = Path.GetFileName(f);
            System.Console.WriteLine($"\n=== {name} ({data.Length}B) ===");

            // Skip LNPBlob (8 bytes)
            if (data.Length <= 8) continue;
            var enc = new byte[data.Length - 8];
            Array.Copy(data, 8, enc, 0, enc.Length);

            System.Console.WriteLine($"  Encrypted ({enc.Length}B): {BitConverter.ToString(enc, 0, Math.Min(24, enc.Length))}");

            // Double CFB decrypt
            var dec = DoubleCfbDecrypt(cipher, enc);
            System.Console.WriteLine($"  DblCFB dec: {BitConverter.ToString(dec, 0, Math.Min(32, dec.Length))}");

            // Parse: [2B peerID][4B nonce][1B flags][payload...]
            if (dec.Length >= 7)
            {
                ushort peerID = (ushort)(dec[0] | (dec[1] << 8));
                uint nonce = (uint)((dec[2] << 24) | (dec[3] << 16) | (dec[4] << 8) | dec[5]);
                byte flags = dec[6];
                byte cmdType = (byte)(flags & 0x7F);
                bool hasTimestamp = (flags & 0x80) != 0;
                System.Console.Write($"  peerID=0x{peerID:X4} nonce=0x{nonce:X8} flags=0x{flags:X2}");
                System.Console.Write($" cmd={cmdType}");
                string[] cmds = {"?","ACK","CONNECT","VERIFY","DISCONNECT","PING","RELIABLE","UNRELIABLE"};
                if (cmdType < cmds.Length) System.Console.Write($"({cmds[cmdType]})");
                System.Console.WriteLine($" hasTS={hasTimestamp}");

                if (hasTimestamp && dec.Length >= 15)
                    System.Console.WriteLine($"  timestamp: {BitConverter.ToString(dec, 7, 8)}");

                int payloadOff = 7 + (hasTimestamp ? 8 : 0);
                if (payloadOff < dec.Length)
                    System.Console.WriteLine($"  payload ({dec.Length - payloadOff}B): {BitConverter.ToString(dec, payloadOff, Math.Min(24, dec.Length - payloadOff))}");
            }

            // Also try single CFB
            var singleDec = CfbDecrypt(cipher, enc);
            System.Console.WriteLine($"  SglCFB dec: {BitConverter.ToString(singleDec, 0, Math.Min(24, singleDec.Length))}");
        }
    }

    static byte[] DoubleCfbDecrypt(BlowFish cipher, byte[] data)
    {
        var result = CfbDecrypt(cipher, data);
        int processed = (result.Length / 8) * 8;
        Array.Reverse(result, 0, processed);
        result = CfbDecrypt(cipher, result);
        return result;
    }

    static byte[] CfbDecrypt(BlowFish cipher, byte[] data)
    {
        var result = new byte[data.Length];
        var feedback = new byte[8];
        for (int i = 0; i < data.Length - 7; i += 8)
        {
            var ks = cipher.EncryptBlock(feedback);
            Array.Copy(data, i, feedback, 0, 8);
            for (int j = 0; j < 8; j++)
                result[i + j] = (byte)(data[i + j] ^ ks[j]);
        }
        int rem = data.Length % 8;
        if (rem > 0)
        {
            int off = data.Length - rem;
            var ks = cipher.EncryptBlock(feedback);
            for (int j = 0; j < rem; j++)
                result[off + j] = (byte)(data[off + j] ^ ks[j]);
        }
        return result;
    }
}
