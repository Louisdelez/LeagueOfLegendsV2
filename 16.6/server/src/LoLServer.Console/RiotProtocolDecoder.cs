using System;
using System.IO;
using System.Linq;
using LoLServer.Core.Network;

namespace LoLServer.Console;

/// <summary>
/// Decode real Riot game server packets captured via Wireshark.
/// Key: jNdWPAc3Vb5AyjoYdkar/g== (game 7805329513, server 162.249.72.5:7342)
/// Run with: dotnet run -- --riot-decode
/// </summary>
public static class RiotProtocolDecoder
{
    public static void Run()
    {
        var realKey = "jNdWPAc3Vb5AyjoYdkar/g==";
        var privateKey = "17BLOhi6KZsTtldTsizvHg==";

        var realCipher = BlowFish.FromBase64(realKey);
        var privateCipher = BlowFish.FromBase64(privateKey);

        System.Console.WriteLine("=== Riot Protocol Decoder ===");
        System.Console.WriteLine($"Real game key: {realKey}");
        System.Console.WriteLine($"Private key:   {privateKey}");
        System.Console.WriteLine();

        // Blowfish reference values
        var zeros = new byte[8];
        var realEncZeros = realCipher.Encrypt(zeros);
        var privateEncZeros = privateCipher.Encrypt(zeros);
        var realDecZeros = realCipher.Decrypt(zeros);
        var privateDecZeros = privateCipher.Decrypt(zeros);

        System.Console.WriteLine($"Real:    Encrypt(zeros) = {Hex(realEncZeros)}");
        System.Console.WriteLine($"Private: Encrypt(zeros) = {Hex(privateEncZeros)}");
        System.Console.WriteLine($"Real:    Decrypt(zeros) = {Hex(realDecZeros)}");
        System.Console.WriteLine($"Private: Decrypt(zeros) = {Hex(privateDecZeros)}");
        System.Console.WriteLine();

        // Load handshake packets from file
        var packetFile = @"D:\LeagueOfLegendsV2\riot_protocol\handshake_packets.txt";
        if (!File.Exists(packetFile))
        {
            System.Console.WriteLine($"[ERROR] {packetFile} not found");
            return;
        }

        var lines = File.ReadAllLines(packetFile).Where(l => l.Trim().Length > 0).ToArray();
        System.Console.WriteLine($"Loaded {lines.Length} packets");
        System.Console.WriteLine();

        foreach (var line in lines.Take(25))
        {
            var parts = line.Split('\t');
            if (parts.Length < 4) continue;

            var frameNum = parts[0].Trim();
            var srcIp = parts[1].Trim();
            var dataLen = parts[2].Trim();
            var hexData = parts[3].Trim();

            if (string.IsNullOrEmpty(hexData)) continue;

            var data = HexToBytes(hexData);
            bool isClient = srcIp.StartsWith("192.168");
            var direction = isClient ? "C→S" : "S→C";

            System.Console.WriteLine($"═══ Frame {frameNum} {direction} {data.Length}B ═══");
            System.Console.WriteLine($"  Raw first 32: {Hex(data, 32)}");

            // Try Blowfish decrypt with real key
            if (data.Length >= 8)
            {
                var decrypted = realCipher.Decrypt(data);
                System.Console.WriteLine($"  Dec first 32: {Hex(decrypted, 32)}");

                // Check if first 8 decrypted bytes match Decrypt(zeros) pattern
                bool checksumMatch = true;
                for (int i = 0; i < 8 && i < decrypted.Length; i++)
                    if (decrypted[i] != realDecZeros[i]) { checksumMatch = false; break; }

                if (checksumMatch)
                    System.Console.WriteLine($"  *** First 8B = Decrypt(zeros) → checksum confirmed!");

                // Parse structure
                if (isClient && data.Length == 519)
                {
                    ParseClientConnect(data, decrypted, realCipher);
                }
                else if (!isClient && data.Length == 111)
                {
                    ParseServerVerify(data, decrypted, realCipher);
                }
                else if (data.Length <= 35)
                {
                    ParseSmallPacket(data, decrypted, realCipher, isClient);
                }
                else
                {
                    ParseGenericPacket(data, decrypted, realCipher, isClient);
                }
            }

            System.Console.WriteLine();
        }

        // Now compare with private server captures
        System.Console.WriteLine("═══════════════════════════════════════════");
        System.Console.WriteLine("COMPARING REAL vs PRIVATE encrypted packets");
        System.Console.WriteLine("═══════════════════════════════════════════");

        // Decrypt private captures with private key
        var privateDir = @"D:\LeagueOfLegendsV2\client-private\Game\nethook_logs";
        if (Directory.Exists(privateDir))
        {
            var sends = Directory.GetFiles(privateDir, "SEND_*.bin").OrderBy(f => f).Take(3).ToArray();
            foreach (var file in sends)
            {
                var data = File.ReadAllBytes(file);
                var dec = privateCipher.Decrypt(data);
                System.Console.WriteLine($"\n--- {Path.GetFileName(file)} ({data.Length}B) ---");
                System.Console.WriteLine($"  Raw first 32: {Hex(data, 32)}");
                System.Console.WriteLine($"  Dec first 32: {Hex(dec, 32)}");

                // Compare structure with real decrypted
                System.Console.WriteLine($"  Dec bytes 0-7 (checksum): {Hex(dec, 8)}");
            }
        }
    }

    static void ParseClientConnect(byte[] raw, byte[] dec, BlowFish cipher)
    {
        System.Console.WriteLine($"  [CLIENT CONNECT 519B]");
        System.Console.WriteLine($"    Raw header:  {Hex(raw, 12)}");

        // After decrypt, analyze structure
        System.Console.WriteLine($"    Dec[0-7]  checksum: {Hex(dec, 8)}");
        System.Console.WriteLine($"    Dec[8-11] field1:   {Hex(dec, 4, 8)}");
        System.Console.WriteLine($"    Dec[12-15] field2:  {Hex(dec, 4, 12)}");
        System.Console.WriteLine($"    Dec[16-19] field3:  {Hex(dec, 4, 16)}");
        System.Console.WriteLine($"    Dec[20-23] field4:  {Hex(dec, 4, 20)}");

        // Check if bytes after checksum look like ENet
        int off = 8;
        if (off + 4 < dec.Length)
        {
            ushort peerID = (ushort)(dec[off] | (dec[off + 1] << 8));
            ushort sentTime = (ushort)(dec[off + 2] | (dec[off + 3] << 8));
            byte cmdByte = dec[off + 4];
            System.Console.WriteLine($"    @8 as ENet: PeerID=0x{peerID:X4} Time=0x{sentTime:X4} Cmd=0x{cmdByte:X2} (type={cmdByte & 0x0F})");
        }

        // Last 4 bytes
        System.Console.WriteLine($"    Last 4B: {Hex(dec, 4, dec.Length - 4)}");
    }

    static void ParseServerVerify(byte[] raw, byte[] dec, BlowFish cipher)
    {
        System.Console.WriteLine($"  [SERVER VERIFY 111B]");
        System.Console.WriteLine($"    Raw header: {Hex(raw, 8)}");

        // After decrypt
        System.Console.WriteLine($"    Dec[0-7]  checksum: {Hex(dec, 8)}");
        System.Console.WriteLine($"    Dec[8-15] block2:   {Hex(dec, 8, 8)}");
        System.Console.WriteLine($"    Dec[16-23] block3:  {Hex(dec, 8, 16)}");

        // Try parsing as ENet after checksum
        int off = 8;
        if (off + 6 < dec.Length)
        {
            ushort peerID = (ushort)(dec[off] | (dec[off + 1] << 8));
            ushort sentTime = (ushort)(dec[off + 2] | (dec[off + 3] << 8));
            byte cmdByte = dec[off + 4];
            byte channel = dec[off + 5];
            System.Console.WriteLine($"    @8 as ENet: PeerID=0x{peerID:X4} Time=0x{sentTime:X4} Cmd=0x{cmdByte:X2} (type={cmdByte & 0x0F}) Ch=0x{channel:X2}");

            if ((cmdByte & 0x0F) == 3) // VERIFY_CONNECT
            {
                System.Console.WriteLine($"    → VERIFY_CONNECT!");
                if (off + 12 + 20 <= dec.Length)
                {
                    ushort seqNo = (ushort)(dec[off + 6] | (dec[off + 7] << 8));
                    // VERIFY body starts at off+8 (after 4B header + 4B cmd header) or off+12?
                    // ENet VERIFY_CONNECT: cmd(1)+channel(1)+seq(2)+padding(4) = 8 bytes header
                    int body = off + 8;
                    ushort outPeerID = (ushort)(dec[body] | (dec[body + 1] << 8));
                    byte inSess = dec[body + 2];
                    byte outSess = dec[body + 3];
                    uint mtu = BitConverter.ToUInt32(dec, body + 4);
                    uint window = BitConverter.ToUInt32(dec, body + 8);
                    uint channels = BitConverter.ToUInt32(dec, body + 12);
                    System.Console.WriteLine($"    SeqNo={seqNo} OutPeerID=0x{outPeerID:X4} Sess={inSess}/{outSess}");
                    System.Console.WriteLine($"    MTU={mtu} Window={window} Channels={channels}");
                }
            }
        }

        System.Console.WriteLine($"    Last 4B: {Hex(dec, 4, dec.Length - 4)}");
    }

    static void ParseSmallPacket(byte[] raw, byte[] dec, BlowFish cipher, bool isClient)
    {
        string dir = isClient ? "CLIENT" : "SERVER";
        System.Console.WriteLine($"  [{dir} {raw.Length}B small packet]");
        System.Console.WriteLine($"    Dec all: {Hex(dec, dec.Length)}");

        // Check ENet ACK format
        if (dec.Length >= 14)
        {
            int off = 8;
            ushort peerID = (ushort)(dec[off] | (dec[off + 1] << 8));
            ushort sentTime = (ushort)(dec[off + 2] | (dec[off + 3] << 8));
            byte cmdByte = dec[off + 4];
            System.Console.WriteLine($"    @8 as ENet: PeerID=0x{peerID:X4} Time=0x{sentTime:X4} Cmd=0x{cmdByte:X2} (type={cmdByte & 0x0F})");
        }
    }

    static void ParseGenericPacket(byte[] raw, byte[] dec, BlowFish cipher, bool isClient)
    {
        string dir = isClient ? "CLIENT" : "SERVER";
        System.Console.WriteLine($"  [{dir} {raw.Length}B]");
        System.Console.WriteLine($"    Dec[0-7]  checksum: {Hex(dec, 8)}");

        int off = 8;
        if (off + 6 < dec.Length)
        {
            ushort peerID = (ushort)(dec[off] | (dec[off + 1] << 8));
            ushort sentTime = (ushort)(dec[off + 2] | (dec[off + 3] << 8));
            byte cmdByte = dec[off + 4];
            byte channel = dec[off + 5];
            int cmdType = cmdByte & 0x0F;
            System.Console.WriteLine($"    @8 as ENet: PeerID=0x{peerID:X4} Time=0x{sentTime:X4} Cmd=0x{cmdByte:X2} (type={cmdType}) Ch=0x{channel:X2}");

            if (cmdType == 6) // RELIABLE
            {
                ushort seqNo = (ushort)(dec[off + 6] | (dec[off + 7] << 8));
                ushort dataLen = 0;
                if (off + 10 <= dec.Length)
                    dataLen = (ushort)(dec[off + 8] | (dec[off + 9] << 8));
                System.Console.WriteLine($"    → RELIABLE Seq={seqNo} DataLen={dataLen}");

                if (off + 10 + dataLen <= dec.Length && dataLen > 0)
                {
                    System.Console.WriteLine($"    Payload first 32: {Hex(dec, Math.Min(32, (int)dataLen), off + 10)}");
                }
            }
            else if (cmdType == 1) // ACK
            {
                System.Console.WriteLine($"    → ACK");
            }
            else if (cmdType == 2) // CONNECT
            {
                System.Console.WriteLine($"    → CONNECT");
            }
        }

        System.Console.WriteLine($"    Last 4B: {Hex(dec, Math.Min(4, dec.Length), Math.Max(0, dec.Length - 4))}");
    }

    static string Hex(byte[] data, int maxLen = 32, int offset = 0)
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
