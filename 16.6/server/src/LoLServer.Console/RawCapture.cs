using System;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace LoLServer.Console;

/// <summary>
/// Raw UDP packet capture tool.
/// Listens on the game port and captures everything the LoL client sends.
/// This bypasses LENet to see the raw protocol bytes.
/// </summary>
public static class RawCapture
{
    public static void Run(int port = 5119)
    {
        System.Console.WriteLine($"=== Raw UDP Capture on port {port} ===");
        System.Console.WriteLine("Waiting for packets from LoL client...");
        System.Console.WriteLine("Launch the client now!");
        System.Console.WriteLine();

        var logDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs", "raw_capture");
        Directory.CreateDirectory(logDir);

        using var socket = new UdpClient(port);
        int packetCount = 0;

        while (packetCount < 200)
        {
            IPEndPoint? remote = null;
            byte[] data;

            try
            {
                data = socket.Receive(ref remote);
            }
            catch (SocketException ex)
            {
                System.Console.WriteLine($"[ERROR] {ex.Message}");
                continue;
            }

            packetCount++;
            var timestamp = DateTime.Now.ToString("HH:mm:ss.fff");

            System.Console.WriteLine($"[{timestamp}] Packet #{packetCount} from {remote} ({data.Length} bytes)");

            // Hex dump first 128 bytes
            var hexLen = Math.Min(128, data.Length);
            System.Console.WriteLine($"  HEX: {BitConverter.ToString(data, 0, hexLen)}");

            // Try to identify ENet header format
            AnalyzePacket(data, packetCount);

            // Save to file
            var filename = Path.Combine(logDir, $"{packetCount:D4}_{data.Length}B.bin");
            File.WriteAllBytes(filename, data);

            // Send back a response for each format we think it might be
            if (packetCount <= 3)
            {
                TryRespondAsENet(socket, remote!, data);
            }

            System.Console.WriteLine();
        }

        System.Console.WriteLine($"Captured {packetCount} packets to {logDir}");
    }

    static void AnalyzePacket(byte[] data, int num)
    {
        if (data.Length < 4) return;

        // ENet protocol header analysis
        // Standard ENet: [peer_id:2][sent_time:2][...commands...]
        // Patch420 ENet: [checksum:4][peer_id:2][sent_time:2][...commands...]
        // Season8+ ENet: [checksum:8][peer_id:2][sent_time:2][...commands...]

        System.Console.WriteLine($"  --- Analysis ---");

        // Try: no checksum header (raw ENet)
        if (data.Length >= 4)
        {
            ushort peerIdRaw = BitConverter.ToUInt16(data, 0);
            ushort sentTimeRaw = BitConverter.ToUInt16(data, 2);
            byte cmdRaw = (data.Length > 4) ? data[4] : (byte)0;
            System.Console.WriteLine($"  [NoChecksum] PeerID=0x{peerIdRaw:X4} SentTime={sentTimeRaw} Cmd=0x{cmdRaw:X2}");
        }

        // Try: 4-byte checksum (Patch 4.20)
        if (data.Length >= 8)
        {
            uint crc32 = BitConverter.ToUInt32(data, 0);
            ushort peerId420 = BitConverter.ToUInt16(data, 4);
            ushort sentTime420 = BitConverter.ToUInt16(data, 6);
            byte cmd420 = (data.Length > 8) ? data[8] : (byte)0;
            int channelCmd420 = cmd420 & 0x0F;
            System.Console.WriteLine($"  [Patch420]   CRC32=0x{crc32:X8} PeerID=0x{peerId420:X4} SentTime={sentTime420} Cmd=0x{cmd420:X2} (channel cmd={channelCmd420})");
        }

        // Try: 8-byte checksum (Season 8+)
        if (data.Length >= 12)
        {
            ulong checksum8 = BitConverter.ToUInt64(data, 0);
            ushort peerId8 = BitConverter.ToUInt16(data, 8);
            ushort sentTime8 = BitConverter.ToUInt16(data, 10);
            byte cmd8 = (data.Length > 12) ? data[12] : (byte)0;
            int channelCmd8 = cmd8 & 0x0F;
            System.Console.WriteLine($"  [Season8+]   Checksum=0x{checksum8:X16} PeerID=0x{peerId8:X4} SentTime={sentTime8} Cmd=0x{cmd8:X2} (channel cmd={channelCmd8})");
        }

        // ENet CONNECT command = 0x02, with header flag 0x80 = SENT_TIME
        // So we look for 0x82 (CONNECT | SENT_TIME) in likely positions
        for (int offset = 0; offset < Math.Min(16, data.Length); offset++)
        {
            if ((data[offset] & 0x0F) == 0x02) // CONNECT command
            {
                System.Console.WriteLine($"  [POSSIBLE CONNECT] Found ENet CONNECT (0x{data[offset]:X2}) at offset {offset} → checksum size = {offset - 4} (before peer_id+sent_time)");
            }
        }
    }

    static void TryRespondAsENet(UdpClient socket, IPEndPoint remote, byte[] data)
    {
        // Build a minimal ENet VERIFY_CONNECT response
        // This helps us figure out if the client accepts any particular format
        System.Console.WriteLine($"  [RESPOND] Sending probe responses to {remote}...");

        // We'll just echo back for now to see if client sends more
        try
        {
            socket.Send(data, data.Length, remote);
        }
        catch { }
    }
}
