using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using LoLServer.Core.Network;

namespace LoLServer.Console;

/// <summary>
/// Advanced packet decoder using insights from r3dlog:
/// - Encryption=true (Blowfish)
/// - Compression=true (zlib level 3)
/// - MinimumSizeToCompressPayloadThreshold=0 (all payloads compressed)
/// Run with: dotnet run -- --decode
/// </summary>
public static class PacketDecoder
{
    // Blowfish key used for our private server captures
    private const string PrivateKey = "17BLOhi6KZsTtldTsizvHg==";

    // Key from real game (captured from LeagueClient logs)
    private const string RealGameKey = "K4gyS9t7q4RaFM0VLUJFJg==";

    public static void Run()
    {
        System.Console.WriteLine("=== LoL Packet Decoder ===");
        System.Console.WriteLine($"Private server key: {PrivateKey}");
        System.Console.WriteLine($"Real game key: {RealGameKey}");
        System.Console.WriteLine();

        // Load captures from client-private
        var captureDir = Path.GetFullPath(Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "..",
            "client-private", "Game", "nethook_logs"));

        if (!Directory.Exists(captureDir))
        {
            // Try direct path
            captureDir = @"D:\LeagueOfLegendsV2\client-private\Game\nethook_logs";
        }

        if (!Directory.Exists(captureDir))
        {
            System.Console.WriteLine($"[ERROR] No capture directory found");
            return;
        }

        System.Console.WriteLine($"Capture dir: {captureDir}");

        var files = Directory.GetFiles(captureDir, "*.bin")
            .OrderBy(f => f)
            .ToArray();

        System.Console.WriteLine($"Found {files.Length} capture files");
        System.Console.WriteLine();

        // Separate SEND and RECV
        var sends = files.Where(f => Path.GetFileName(f).StartsWith("SEND")).ToArray();
        var recvs = files.Where(f => Path.GetFileName(f).StartsWith("RECV")).ToArray();
        System.Console.WriteLine($"SEND: {sends.Length} files, RECV: {recvs.Length} files");

        // Show size distribution
        var sizes = files.Select(f => new FileInfo(f).Length).GroupBy(s => s)
            .OrderByDescending(g => g.Count());
        System.Console.WriteLine("\nSize distribution:");
        foreach (var g in sizes.Take(10))
            System.Console.WriteLine($"  {g.Key}B: {g.Count()} files");

        System.Console.WriteLine("\n" + new string('=', 80));
        System.Console.WriteLine("PHASE 1: Analyze raw packet structure");
        System.Console.WriteLine(new string('=', 80));

        AnalyzePacketStructure(sends.Take(5).ToArray(), recvs.Take(5).ToArray());

        System.Console.WriteLine("\n" + new string('=', 80));
        System.Console.WriteLine("PHASE 2: Brute-force decryption strategies");
        System.Console.WriteLine(new string('=', 80));

        var cipher = BlowFish.FromBase64(PrivateKey);
        var realCipher = BlowFish.FromBase64(RealGameKey);

        // Test first SEND packet with both keys
        if (sends.Length > 0)
        {
            var data = File.ReadAllBytes(sends[0]);
            System.Console.WriteLine($"\nTesting {Path.GetFileName(sends[0])} ({data.Length}B)");
            System.Console.WriteLine($"Raw hex (first 64): {BitConverter.ToString(data, 0, Math.Min(64, data.Length))}");

            TryAllDecryptStrategies(data, cipher, "PrivateKey");
            TryAllDecryptStrategies(data, realCipher, "RealGameKey");
        }

        // Test first RECV packet (our server's responses)
        if (recvs.Length > 0)
        {
            var data = File.ReadAllBytes(recvs[0]);
            System.Console.WriteLine($"\nTesting {Path.GetFileName(recvs[0])} ({data.Length}B)");
            System.Console.WriteLine($"Raw hex (all): {BitConverter.ToString(data, 0, Math.Min(64, data.Length))}");

            TryAllDecryptStrategies(data, cipher, "PrivateKey");
        }

        System.Console.WriteLine("\n" + new string('=', 80));
        System.Console.WriteLine("PHASE 3: Compare multiple SEND packets to find variable fields");
        System.Console.WriteLine(new string('=', 80));

        ComparePackets(sends.Take(10).ToArray());

        System.Console.WriteLine("\n" + new string('=', 80));
        System.Console.WriteLine("PHASE 4: Try zlib decompression at various offsets");
        System.Console.WriteLine(new string('=', 80));

        if (sends.Length > 0)
        {
            var data = File.ReadAllBytes(sends[0]);
            TryZlibDecompression(data, cipher, "SEND[0]");
        }

        System.Console.WriteLine("\n" + new string('=', 80));
        System.Console.WriteLine("PHASE 5: Analyze RECV packets (our server responses)");
        System.Console.WriteLine(new string('=', 80));

        foreach (var recv in recvs.Take(10))
        {
            var data = File.ReadAllBytes(recv);
            var name = Path.GetFileName(recv);
            System.Console.WriteLine($"\n--- {name} ({data.Length}B) ---");
            System.Console.WriteLine($"  Hex: {BitConverter.ToString(data)}");
        }

        System.Console.WriteLine("\n" + new string('=', 80));
        System.Console.WriteLine("PHASE 6: Deep zlib analysis (decrypt full → decompress)");
        System.Console.WriteLine(new string('=', 80));

        var firstSendPackets = sends.Take(5).Select(f => File.ReadAllBytes(f)).ToArray();
        DeepZlibAnalysis(firstSendPackets, cipher);

        System.Console.WriteLine("\n" + new string('=', 80));
        System.Console.WriteLine("PHASE 7: Detailed RECV analysis (our server responses)");
        System.Console.WriteLine(new string('=', 80));

        AnalyzeRecvPackets(recvs.Take(15).ToArray(), cipher);

        System.Console.WriteLine("\n" + new string('=', 80));
        System.Console.WriteLine("PHASE 8: Check if 519B = 8-byte header + encrypted(compressed(ENet))");
        System.Console.WriteLine(new string('=', 80));

        if (sends.Length >= 3)
        {
            for (int i = 0; i < Math.Min(3, sends.Length); i++)
            {
                var data = File.ReadAllBytes(sends[i]);
                System.Console.WriteLine($"\n--- {Path.GetFileName(sends[i])} ---");
                TryHeaderPlusEncryptedCompressed(data, cipher, "PrivateKey");
            }
        }
    }

    static void AnalyzePacketStructure(byte[][] sends, byte[][] recvs)
    {
        // Placeholder
    }

    static void AnalyzePacketStructure(string[] sendFiles, string[] recvFiles)
    {
        if (sendFiles.Length < 2) return;

        var packets = sendFiles.Select(f => File.ReadAllBytes(f)).ToArray();

        System.Console.WriteLine($"\nComparing {packets.Length} SEND packets:");

        // Find constant bytes across all packets
        if (packets.All(p => p.Length == packets[0].Length))
        {
            int len = packets[0].Length;
            var constBytes = new StringBuilder();
            var varBytes = new StringBuilder();
            int constCount = 0;

            for (int i = 0; i < len; i++)
            {
                bool isConst = packets.All(p => p[i] == packets[0][i]);
                if (isConst)
                {
                    constCount++;
                    if (constCount <= 100) // Log first 100
                        constBytes.Append($"  [{i:D3}] = 0x{packets[0][i]:X2}\n");
                }
                else
                {
                    var values = string.Join(",", packets.Select(p => $"0x{p[i]:X2}"));
                    if (varBytes.Length < 2000) // Limit output
                        varBytes.Append($"  [{i:D3}] varies: {values}\n");
                }
            }

            System.Console.WriteLine($"\nConstant bytes: {constCount}/{len}");
            System.Console.WriteLine($"Variable bytes: {len - constCount}/{len}");
            System.Console.WriteLine($"\nFirst variable byte positions:");
            System.Console.Write(varBytes.ToString());
        }
    }

    static void TryAllDecryptStrategies(byte[] data, BlowFish cipher, string keyName)
    {
        System.Console.WriteLine($"\n  --- Strategies with {keyName} ---");

        // Strategy 1: Full decrypt (offset 0)
        TryDecryptAt(data, cipher, 0, $"Full decrypt @0");

        // Strategy 2: Skip 8-byte checksum
        TryDecryptAt(data, cipher, 8, $"Decrypt @8 (skip checksum)");

        // Strategy 3: Skip 4-byte checksum
        TryDecryptAt(data, cipher, 4, $"Decrypt @4");

        // Strategy 4: Skip 15-byte header (8+7 constant bytes we identified)
        TryDecryptAt(data, cipher, 15, $"Decrypt @15 (skip header)");

        // Strategy 5: Skip 16-byte header
        TryDecryptAt(data, cipher, 16, $"Decrypt @16");

        // Strategy 6: Decrypt first 8 bytes only
        if (data.Length >= 8)
        {
            var block = new byte[8];
            Array.Copy(data, block, 8);
            var dec = cipher.Decrypt(block);
            var enc = cipher.Encrypt(block);
            System.Console.WriteLine($"  [Dec first 8B] {BitConverter.ToString(block)} → Dec:{BitConverter.ToString(dec)} Enc:{BitConverter.ToString(enc)}");
        }

        // Strategy 7: Encrypt (maybe client used Encrypt, not Decrypt, to scramble)
        TryEncryptAt(data, cipher, 0, "Encrypt @0 (reverse)");
        TryEncryptAt(data, cipher, 8, "Encrypt @8 (reverse)");
    }

    static void TryDecryptAt(byte[] data, BlowFish cipher, int offset, string label)
    {
        if (offset >= data.Length) return;
        var segment = new byte[data.Length - offset];
        Array.Copy(data, offset, segment, 0, segment.Length);

        var decrypted = cipher.Decrypt(segment);

        // Check for ENet signatures
        bool looksLikeENet = false;
        string enetInfo = "";

        if (decrypted.Length >= 6)
        {
            // Check various ENet header positions
            for (int hdr = 0; hdr <= Math.Min(8, decrypted.Length - 5); hdr += 4)
            {
                byte cmdByte = decrypted[hdr + 4];
                int cmd = cmdByte & 0x0F;
                if (cmd >= 1 && cmd <= 7)
                {
                    ushort peerID = (ushort)(decrypted[hdr] | (decrypted[hdr + 1] << 8));
                    ushort sentTime = (ushort)(decrypted[hdr + 2] | (decrypted[hdr + 3] << 8));
                    looksLikeENet = true;
                    enetInfo = $" → ENet@{hdr}! PeerID=0x{peerID:X4} Time=0x{sentTime:X4} Cmd={cmd}";
                    break;
                }
            }
        }

        // Check for zlib header (0x78)
        bool hasZlib = false;
        for (int i = 0; i < Math.Min(20, decrypted.Length); i++)
        {
            if (decrypted[i] == 0x78 && i + 1 < decrypted.Length &&
                (decrypted[i + 1] == 0x01 || decrypted[i + 1] == 0x5E ||
                 decrypted[i + 1] == 0x9C || decrypted[i + 1] == 0xDA))
            {
                hasZlib = true;
                enetInfo += $" ZLIB@{i}(0x{decrypted[i]:X2}{decrypted[i + 1]:X2})";
            }
        }

        var marker = looksLikeENet ? " <<<" : (hasZlib ? " <<ZLIB" : "");
        System.Console.WriteLine($"  [{label}] {BitConverter.ToString(decrypted, 0, Math.Min(24, decrypted.Length))}{enetInfo}{marker}");
    }

    static void TryEncryptAt(byte[] data, BlowFish cipher, int offset, string label)
    {
        if (offset >= data.Length) return;
        var segment = new byte[data.Length - offset];
        Array.Copy(data, offset, segment, 0, segment.Length);

        var encrypted = cipher.Encrypt(segment);

        // Check for ENet or zlib
        if (encrypted.Length >= 6)
        {
            for (int hdr = 0; hdr <= 8 && hdr + 4 < encrypted.Length; hdr += 4)
            {
                byte cmdByte = encrypted[hdr + 4];
                int cmd = cmdByte & 0x0F;
                if (cmd >= 1 && cmd <= 7)
                {
                    ushort peerID = (ushort)(encrypted[hdr] | (encrypted[hdr + 1] << 8));
                    System.Console.WriteLine($"  [{label}] {BitConverter.ToString(encrypted, 0, Math.Min(24, encrypted.Length))} → ENet@{hdr}! PeerID=0x{peerID:X4} Cmd={cmd} <<<");
                    return;
                }
            }
        }

        System.Console.WriteLine($"  [{label}] {BitConverter.ToString(encrypted, 0, Math.Min(24, encrypted.Length))}");
    }

    static void ComparePackets(string[] files)
    {
        if (files.Length < 2) return;
        var packets = files.Select(f => File.ReadAllBytes(f)).ToArray();

        if (!packets.All(p => p.Length == packets[0].Length))
        {
            System.Console.WriteLine("Packets have different sizes, can't compare directly");
            return;
        }

        int len = packets[0].Length;
        System.Console.WriteLine($"Comparing {packets.Length} packets, each {len} bytes");

        // Group bytes: constant vs variable
        var constRanges = new System.Collections.Generic.List<(int start, int end, byte val)>();
        var varPositions = new System.Collections.Generic.List<int>();

        int rangeStart = -1;
        for (int i = 0; i < len; i++)
        {
            bool isConst = packets.All(p => p[i] == packets[0][i]);
            if (isConst)
            {
                if (rangeStart == -1) rangeStart = i;
            }
            else
            {
                if (rangeStart != -1)
                {
                    constRanges.Add((rangeStart, i - 1, packets[0][rangeStart]));
                    rangeStart = -1;
                }
                varPositions.Add(i);
            }
        }
        if (rangeStart != -1)
            constRanges.Add((rangeStart, len - 1, packets[0][rangeStart]));

        System.Console.WriteLine($"\nConstant ranges ({constRanges.Count}):");
        foreach (var (start, end, val) in constRanges.Take(20))
        {
            if (end - start > 3)
                System.Console.WriteLine($"  [{start:D3}-{end:D3}] ({end - start + 1}B) = {BitConverter.ToString(packets[0], start, Math.Min(16, end - start + 1))}...");
            else
                System.Console.WriteLine($"  [{start:D3}-{end:D3}] ({end - start + 1}B) = {BitConverter.ToString(packets[0], start, end - start + 1)}");
        }

        System.Console.WriteLine($"\nVariable positions ({varPositions.Count}):");
        foreach (var pos in varPositions.Take(30))
        {
            var vals = string.Join(" ", packets.Select(p => $"{p[pos]:X2}"));
            System.Console.WriteLine($"  [{pos:D3}]: {vals}");
        }

        // Interesting: check if variable bytes show incrementing pattern (sequence numbers)
        System.Console.WriteLine($"\nSequence analysis on variable bytes:");
        foreach (var pos in varPositions.Take(10))
        {
            var vals = packets.Select(p => (int)p[pos]).ToArray();
            bool incrementing = true;
            for (int i = 1; i < vals.Length; i++)
                if (vals[i] <= vals[i - 1]) { incrementing = false; break; }

            if (incrementing)
                System.Console.WriteLine($"  [{pos:D3}] INCREMENTING: {string.Join(",", vals)}");
        }
    }

    static void TryZlibDecompression(byte[] data, BlowFish cipher, string label)
    {
        System.Console.WriteLine($"\nTrying zlib decompression on {label} ({data.Length}B)");

        // Try raw data at various offsets
        foreach (int offset in new[] { 0, 4, 8, 15, 16, 20 })
        {
            TryDeflateAt(data, offset, $"Raw @{offset}");
        }

        // Try after Blowfish decrypt at various offsets
        foreach (int decOffset in new[] { 0, 8 })
        {
            var segment = new byte[data.Length - decOffset];
            Array.Copy(data, decOffset, segment, 0, segment.Length);
            var decrypted = cipher.Decrypt(segment);

            foreach (int zlibOffset in new[] { 0, 4, 6, 8, 12 })
            {
                TryDeflateAt(decrypted, zlibOffset, $"Dec@{decOffset}+Zlib@{zlibOffset}");
            }
        }
    }

    static void TryDeflateAt(byte[] data, int offset, string label)
    {
        if (offset + 2 >= data.Length) return;

        try
        {
            using var input = new MemoryStream(data, offset, data.Length - offset);
            using var deflate = new DeflateStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();
            deflate.CopyTo(output);
            var result = output.ToArray();
            if (result.Length > 0)
            {
                System.Console.WriteLine($"  [{label}] DECOMPRESSED! {data.Length - offset}B → {result.Length}B");
                System.Console.WriteLine($"    First 32: {BitConverter.ToString(result, 0, Math.Min(32, result.Length))}");

                // Check if decompressed looks like ENet
                if (result.Length >= 6)
                {
                    byte cmd = (byte)(result[4] & 0x0F);
                    if (cmd >= 1 && cmd <= 7)
                        System.Console.WriteLine($"    → Possible ENet! Cmd={cmd}");
                }
            }
        }
        catch { /* not valid deflate */ }

        // Also try with zlib header (skip 2-byte header)
        if (offset + 4 < data.Length && data[offset] == 0x78)
        {
            try
            {
                using var input = new MemoryStream(data, offset + 2, data.Length - offset - 2);
                using var deflate = new DeflateStream(input, CompressionMode.Decompress);
                using var output = new MemoryStream();
                deflate.CopyTo(output);
                var result = output.ToArray();
                if (result.Length > 0)
                {
                    System.Console.WriteLine($"  [{label}+skip_zlib_hdr] DECOMPRESSED! → {result.Length}B");
                    System.Console.WriteLine($"    First 32: {BitConverter.ToString(result, 0, Math.Min(32, result.Length))}");
                }
            }
            catch { /* not valid */ }
        }
    }

    static void DeepZlibAnalysis(byte[][] packets, BlowFish cipher)
    {
        System.Console.WriteLine("\n=== DEEP ZLIB ANALYSIS ===");
        System.Console.WriteLine("Strategy: Blowfish ECB decrypt full 519B, then zlib decompress at offset 4");
        System.Console.WriteLine();

        for (int i = 0; i < packets.Length; i++)
        {
            var data = packets[i];
            var decrypted = cipher.Decrypt(data);

            // The first 8 decrypted bytes are the same for all packets (checksum)
            // Bytes [0-3] after decrypt = ENet header? Bytes [4+] = compressed payload?

            // Try deflate at every offset in decrypted data
            for (int off = 0; off < Math.Min(32, decrypted.Length - 2); off++)
            {
                try
                {
                    using var input = new MemoryStream(decrypted, off, decrypted.Length - off);
                    using var deflate = new DeflateStream(input, CompressionMode.Decompress);
                    using var output = new MemoryStream();
                    deflate.CopyTo(output);
                    var result = output.ToArray();
                    if (result.Length > 2)
                    {
                        System.Console.WriteLine($"  Packet[{i}] Dec+Zlib@{off}: {decrypted.Length - off}B → {result.Length}B");
                        System.Console.WriteLine($"    Header (pre-zlib): {BitConverter.ToString(decrypted, 0, Math.Min(off + 4, decrypted.Length))}");
                        System.Console.WriteLine($"    Decompressed: {BitConverter.ToString(result, 0, Math.Min(64, result.Length))}");

                        // Try to identify the decompressed content
                        if (result.Length >= 4)
                        {
                            // Check for ENet command
                            for (int hdr = 0; hdr <= Math.Min(8, result.Length - 2); hdr += 2)
                            {
                                if (hdr + 1 < result.Length)
                                {
                                    byte b = result[hdr];
                                    int cmd = b & 0x0F;
                                    if (cmd >= 1 && cmd <= 7)
                                        System.Console.WriteLine($"    Possible ENet cmd={cmd} at decompressed[{hdr}]");
                                }
                            }
                        }

                        // Print ASCII if any
                        var ascii = new StringBuilder();
                        foreach (var b in result)
                            ascii.Append(b >= 0x20 && b < 0x7F ? (char)b : '.');
                        System.Console.WriteLine($"    ASCII: {ascii}");
                    }
                }
                catch { }
            }
        }
    }

    static void AnalyzeRecvPackets(string[] recvFiles, BlowFish cipher)
    {
        System.Console.WriteLine("\n=== DETAILED RECV ANALYSIS ===");

        foreach (var file in recvFiles)
        {
            var data = File.ReadAllBytes(file);
            var name = Path.GetFileName(file);
            System.Console.WriteLine($"\n--- {name} ({data.Length}B) ---");
            System.Console.WriteLine($"  Raw: {BitConverter.ToString(data)}");

            // Decrypt
            var dec = cipher.Decrypt(data);
            System.Console.WriteLine($"  Dec: {BitConverter.ToString(dec)}");

            // Parse as ENet
            if (dec.Length >= 6)
            {
                // Try with 8-byte checksum prefix (first 8 bytes = checksum, then ENet)
                if (dec.Length >= 14)
                {
                    ushort peerID = (ushort)(dec[8] | (dec[9] << 8));
                    ushort sentTime = (ushort)(dec[10] | (dec[11] << 8));
                    byte cmdByte = dec[12];
                    byte channel = dec[13];
                    int cmd = cmdByte & 0x0F;
                    bool hasSentTime = (cmdByte & 0x80) != 0;
                    System.Console.WriteLine($"  [8B-checksum] PeerID=0x{peerID:X4} Time={sentTime} Cmd={cmd} HasST={hasSentTime} Chan={channel}");

                    if (cmd == 1) System.Console.WriteLine($"    → ACK");
                    if (cmd == 2) System.Console.WriteLine($"    → CONNECT");
                    if (cmd == 3) System.Console.WriteLine($"    → VERIFY_CONNECT");
                    if (cmd == 5) System.Console.WriteLine($"    → PING");
                    if (cmd == 6) System.Console.WriteLine($"    → RELIABLE");
                }

                // Try without checksum (raw ENet at offset 0)
                {
                    ushort peerID = (ushort)(dec[0] | (dec[1] << 8));
                    ushort sentTime = (ushort)(dec[2] | (dec[3] << 8));
                    byte cmdByte = dec[4];
                    byte channel = dec[5];
                    int cmd = cmdByte & 0x0F;
                    bool hasSentTime = (cmdByte & 0x80) != 0;
                    System.Console.WriteLine($"  [no-checksum] PeerID=0x{peerID:X4} Time={sentTime} Cmd={cmd} HasST={hasSentTime} Chan={channel}");
                }
            }

            // Check if it's plaintext ENet (not encrypted)
            if (data.Length >= 6)
            {
                byte cmdByte = data[4];
                int cmd = cmdByte & 0x0F;
                if (cmd >= 1 && cmd <= 7)
                {
                    ushort peerID = (ushort)(data[0] | (data[1] << 8));
                    System.Console.WriteLine($"  [PLAINTEXT] PeerID=0x{peerID:X4} Cmd={cmd} CmdByte=0x{cmdByte:X2}");
                }
            }
        }
    }

    static void TryHeaderPlusEncryptedCompressed(byte[] data, BlowFish cipher, string keyName)
    {
        System.Console.WriteLine($"  Using key: {keyName}");

        // Hypothesis: [8B checksum][ENet header: peerID(2) + time(2) + cmd(1) + ...][encrypted+compressed payload]
        // The first 8 bytes (all zeros) become the Blowfish checksum when encrypted
        // Then the ENet header follows, also encrypted

        // Try: decrypt entire packet, then check if payload at various offsets is zlib
        foreach (int headerSize in new[] { 0, 4, 8, 12, 16 })
        {
            if (headerSize >= data.Length) continue;

            var toDecrypt = new byte[data.Length - headerSize];
            Array.Copy(data, headerSize, toDecrypt, 0, toDecrypt.Length);
            var decrypted = cipher.Decrypt(toDecrypt);

            System.Console.WriteLine($"  [Header={headerSize}B] Decrypted first 32: {BitConverter.ToString(decrypted, 0, Math.Min(32, decrypted.Length))}");

            // Look for ENet header in decrypted data
            for (int enetOff = 0; enetOff <= 8 && enetOff + 12 < decrypted.Length; enetOff += 4)
            {
                byte cmdByte = decrypted[enetOff + 4];
                int cmd = cmdByte & 0x0F;
                byte channel = decrypted[enetOff + 5];

                if (cmd == 2 && channel == 0xFF) // CONNECT
                {
                    ushort peerID = (ushort)(decrypted[enetOff] | (decrypted[enetOff + 1] << 8));
                    System.Console.WriteLine($"    >>> CONNECT found at ENet@{enetOff}! PeerID=0x{peerID:X4} <<<");

                    // Parse CONNECT body
                    int bodyOff = enetOff + 12; // cmd header is 12 bytes
                    if (bodyOff + 28 <= decrypted.Length)
                    {
                        ushort outPeerID = (ushort)(decrypted[bodyOff] | (decrypted[bodyOff + 1] << 8));
                        byte inSessionID = decrypted[bodyOff + 2];
                        byte outSessionID = decrypted[bodyOff + 3];
                        uint mtu = BitConverter.ToUInt32(decrypted, bodyOff + 4);
                        uint window = BitConverter.ToUInt32(decrypted, bodyOff + 8);
                        uint channels = BitConverter.ToUInt32(decrypted, bodyOff + 12);
                        System.Console.WriteLine($"    OutPeerID=0x{outPeerID:X4} InSession={inSessionID} OutSession={outSessionID}");
                        System.Console.WriteLine($"    MTU={mtu} Window={window} Channels={channels}");
                    }
                }

                if (cmd >= 1 && cmd <= 7)
                {
                    System.Console.WriteLine($"    ENet@{enetOff}: Cmd={cmd} Chan=0x{channel:X2}");
                }
            }

            // Try zlib decompression on various parts of decrypted data
            foreach (int zlibOff in new[] { 4, 6, 8, 12, 16, 20 })
            {
                if (zlibOff + 2 >= decrypted.Length) continue;
                try
                {
                    using var input = new MemoryStream(decrypted, zlibOff, decrypted.Length - zlibOff);
                    using var deflate = new DeflateStream(input, CompressionMode.Decompress);
                    using var output = new MemoryStream();
                    deflate.CopyTo(output);
                    var result = output.ToArray();
                    if (result.Length > 2)
                    {
                        System.Console.WriteLine($"    ZLIB@{zlibOff}: {decrypted.Length - zlibOff}B → {result.Length}B !!!");
                        System.Console.WriteLine($"    Decompressed: {BitConverter.ToString(result, 0, Math.Min(32, result.Length))}");
                    }
                }
                catch { }
            }
        }
    }
}
