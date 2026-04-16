using System;
using System.IO;
using System.Linq;
using LoLServer.Core.Network;

namespace LoLServer.Console;

/// <summary>
/// Analyzes captured raw packets from the modern LoL client
/// to reverse-engineer the protocol format.
/// </summary>
public static class ProtocolAnalyzer
{
    public static void Run()
    {
        var captureDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs", "raw_capture");
        if (!Directory.Exists(captureDir))
        {
            System.Console.WriteLine("[ERROR] No capture directory found. Run --capture first.");
            return;
        }

        var files = Directory.GetFiles(captureDir, "*.bin").OrderBy(f => f).ToArray();
        System.Console.WriteLine($"=== Protocol Analyzer ===");
        System.Console.WriteLine($"Found {files.Length} captured packets in {captureDir}");
        System.Console.WriteLine();

        // Load Blowfish cipher with the key we passed to the client
        var blowfishKey = "17BLOhi6KZsTtldTsizvHg==";
        var cipher = BlowFish.FromBase64(blowfishKey);

        foreach (var file in files.Take(5))
        {
            var data = File.ReadAllBytes(file);
            var name = Path.GetFileName(file);
            System.Console.WriteLine($"=== {name} ({data.Length} bytes) ===");

            // Show raw header
            System.Console.WriteLine($"  Raw[0:16]: {BitConverter.ToString(data, 0, Math.Min(16, data.Length))}");

            // The packet format appears to be: [8B checksum][payload...]
            // Try different interpretations

            // 1. Try: 8-byte header + Blowfish-encrypted ENet data
            if (data.Length > 8)
            {
                var payload = new byte[data.Length - 8];
                Array.Copy(data, 8, payload, 0, payload.Length);

                System.Console.WriteLine($"  Payload (after 8B header): {BitConverter.ToString(payload, 0, Math.Min(16, payload.Length))}");

                // Try Blowfish decrypt on payload
                try
                {
                    var decrypted = cipher.Decrypt(payload);
                    System.Console.WriteLine($"  BF-Decrypt: {BitConverter.ToString(decrypted, 0, Math.Min(32, decrypted.Length))}");

                    // Check if decrypted looks like ENet
                    AnalyzeAsENet(decrypted, "  BF[8:]");
                }
                catch (Exception ex)
                {
                    System.Console.WriteLine($"  BF-Decrypt failed: {ex.Message}");
                }
            }

            // 2. Try: no header, entire packet is Blowfish encrypted
            try
            {
                var decryptedFull = cipher.Decrypt(data);
                System.Console.WriteLine($"  BF-Full: {BitConverter.ToString(decryptedFull, 0, Math.Min(32, decryptedFull.Length))}");
                AnalyzeAsENet(decryptedFull, "  BF-Full");
            }
            catch { }

            // 3. Try: Blowfish decrypt just the first 8 bytes (checksum might be encrypted)
            if (data.Length >= 8)
            {
                var first8 = new byte[8];
                Array.Copy(data, first8, 8);
                try
                {
                    var decFirst = cipher.DecryptBlock(first8);
                    System.Console.WriteLine($"  BF-First8: {BitConverter.ToString(decFirst)}");
                }
                catch { }
            }

            // 4. Try: XOR-based checksum interpretation
            if (data.Length >= 12)
            {
                // Maybe it's [8B zeros][2B peerID][2B sentTime][...] unencrypted
                // With the data AFTER byte 12 being encrypted
                var header = new byte[4];
                Array.Copy(data, 8, header, 0, 4);
                System.Console.WriteLine($"  Header@8: PeerID=0x{BitConverter.ToUInt16(data, 8):X4} SentTime=0x{BitConverter.ToUInt16(data, 10):X4}");

                // Try decrypt starting at byte 12
                if (data.Length > 12)
                {
                    var cmdPayload = new byte[data.Length - 12];
                    Array.Copy(data, 12, cmdPayload, 0, cmdPayload.Length);
                    try
                    {
                        var decCmd = cipher.Decrypt(cmdPayload);
                        System.Console.WriteLine($"  BF[12:]: {BitConverter.ToString(decCmd, 0, Math.Min(32, decCmd.Length))}");
                        // Check first byte for ENet command
                        byte cmd = decCmd[0];
                        System.Console.WriteLine($"    Cmd=0x{cmd:X2} ({cmd & 0x0F}={GetCommandName(cmd & 0x0F)}) flags=0x{cmd & 0xF0:X2}");
                    }
                    catch { }
                }
            }

            // 5. Compare with packet #2 to find varying bytes
            if (files.Length > 1 && file == files[0])
            {
                var data2 = File.ReadAllBytes(files[1]);
                System.Console.WriteLine($"\n  Diff with packet #2:");
                int firstDiff = -1;
                int diffCount = 0;
                for (int i = 0; i < Math.Min(data.Length, data2.Length); i++)
                {
                    if (data[i] != data2[i])
                    {
                        if (firstDiff == -1) firstDiff = i;
                        diffCount++;
                    }
                }
                System.Console.WriteLine($"    First different byte at offset {firstDiff}");
                System.Console.WriteLine($"    Total different bytes: {diffCount}/{data.Length}");
                System.Console.WriteLine($"    Identical header size: {firstDiff} bytes");
            }

            System.Console.WriteLine();
        }
    }

    static void AnalyzeAsENet(byte[] data, string prefix)
    {
        if (data.Length < 4) return;

        // Standard ENet header: [peerID:2][sentTime:2]
        ushort peerID = BitConverter.ToUInt16(data, 0);
        ushort sentTime = BitConverter.ToUInt16(data, 2);

        System.Console.WriteLine($"{prefix} ENet: PeerID=0x{peerID:X4} SentTime={sentTime}");

        if (data.Length >= 5)
        {
            byte cmdByte = data[4];
            int cmd = cmdByte & 0x0F;
            int flags = (cmdByte >> 4) & 0x0F;

            System.Console.WriteLine($"{prefix} Cmd[4]=0x{cmdByte:X2} → cmd={cmd}({GetCommandName(cmd)}) flags={flags:X}");

            // If it's CONNECT (cmd=2), parse the connect body
            if (cmd == 2 && data.Length >= 48)
            {
                System.Console.WriteLine($"{prefix} *** LOOKS LIKE CONNECT! ***");
                // channelID at [5], reliableSeqNo at [6:8]
                // outgoingPeerID at [8:10], incomingSessionID at [10], outgoingSessionID at [11]
                // mtu at [12:16], windowSize at [16:20], channelCount at [20:24]
                System.Console.WriteLine($"{prefix}   channelID={data[5]} seqNo={BitConverter.ToUInt16(data, 6)}");
                System.Console.WriteLine($"{prefix}   outPeerID={BitConverter.ToUInt16(data, 8)} inSession={data[10]} outSession={data[11]}");
                System.Console.WriteLine($"{prefix}   mtu={BitConverter.ToUInt32(data, 12)} window={BitConverter.ToUInt32(data, 16)}");
                System.Console.WriteLine($"{prefix}   channels={BitConverter.ToUInt32(data, 20)}");
            }

            // If peerID is 0xFFFF, this is definitely a CONNECT
            if (peerID == 0xFFFF)
            {
                System.Console.WriteLine($"{prefix} *** PeerID=0xFFFF → Initial CONNECT packet! ***");
            }
        }
    }

    static string GetCommandName(int cmd)
    {
        return cmd switch
        {
            0 => "NONE",
            1 => "ACK",
            2 => "CONNECT",
            3 => "VERIFY_CONNECT",
            4 => "DISCONNECT",
            5 => "PING",
            6 => "RELIABLE",
            7 => "UNRELIABLE",
            8 => "FRAGMENT",
            9 => "UNSEQUENCED",
            10 => "BANDWIDTH_LIMIT",
            11 => "THROTTLE_CONFIGURE",
            12 => "UNRELIABLE_FRAGMENT",
            _ => $"UNKNOWN({cmd})"
        };
    }
}
