using System;
using System.IO;
using System.Linq;
using LoLServer.Core.Network;

namespace LoLServer.Console;

/// <summary>
/// Comprehensive decryption cracker for captured LoL packets.
/// Based on Ghidra decompilation of FUN_1410f41e0 and FUN_14058ef90.
///
/// Encryption algorithm (confirmed):
///   1. CFB encrypt with Blowfish (mode=2, IV=0)
///   2. Reverse entire encrypted buffer
///   3. CFB encrypt again (mode=2, IV=0 - context not updated between calls)
///
/// Decryption (our server):
///   1. CFB decrypt (IV=0)  - undo pass 2
///   2. Reverse buffer
///   3. CFB decrypt (IV=0)  - undo pass 1
///
/// Run with: dotnet run -- --crack
/// </summary>
public static class PacketCrack
{
    // The ACTUAL key used by our private server (from gameconfig.json)
    static readonly string BlowfishKeyB64 = "17BLOhi6KZsTtldTsizvHg==";

    public static void Run()
    {
        var captureDir = @"D:\LeagueOfLegendsV2\client-private\Game\nethook_logs";
        var cipherConfig = BlowFish.FromBase64(BlowfishKeyB64);
        var keyBytes = Convert.FromBase64String(BlowfishKeyB64);

        // Use the config key directly (P-box verified to match captured context in LE)
        var cipher = cipherConfig;

        System.Console.WriteLine($"Blowfish key: {BitConverter.ToString(keyBytes)} ({keyBytes.Length}B)");
        System.Console.WriteLine($"BF_encrypt(zeros) = {BitConverter.ToString(cipher.EncryptBlock(new byte[8]))}");
        System.Console.WriteLine($"P[0] = 0x{cipher.PBox[0]:X8}");
        System.Console.WriteLine();

        var sendFiles = Directory.GetFiles(captureDir, "SEND_*.bin").OrderBy(f => f).Take(5).ToArray();
        var recvFiles = Directory.GetFiles(captureDir, "RECV_*.bin").OrderBy(f => f).Take(5).ToArray();
        var packets = sendFiles.Select(f => (Name: Path.GetFileName(f), Data: File.ReadAllBytes(f))).ToArray();
        var recvPkts = recvFiles.Select(f => (Name: Path.GetFileName(f), Data: File.ReadAllBytes(f))).ToArray();

        // Header/footer analysis
        System.Console.WriteLine("=== PACKET STRUCTURE ===");
        System.Console.WriteLine($"Packet size: {packets[0].Data.Length}");
        System.Console.Write("Constant header: ");
        int constEnd = 0;
        for (int i = 0; i < 20; i++)
        {
            if (packets.All(p => p.Data[i] == packets[0].Data[i]))
                constEnd = i + 1;
            else break;
        }
        System.Console.WriteLine($"{constEnd} bytes: {BitConverter.ToString(packets[0].Data, 0, constEnd)}");
        System.Console.WriteLine($"Footer: {BitConverter.ToString(packets[0].Data, 517, 2)} (constant={packets.All(p => p.Data[517] == 0xED && p.Data[518] == 0xF9)})");
        System.Console.WriteLine();

        // ====================================================================
        // DOUBLE CFB DECRYPTION (from Ghidra decompilation)
        // ====================================================================
        System.Console.WriteLine("=== DOUBLE CFB DECRYPT (Ghidra algorithm) ===");
        System.Console.WriteLine("Algorithm: CFB_decrypt(IV=0) → reverse → CFB_decrypt(IV=0)");
        System.Console.WriteLine();

        // Try various encrypted region boundaries
        int[][] ranges = {
            new[] {8, 517},    // After LNPBlob, before footer
            new[] {8, 519},    // After LNPBlob, to end
            new[] {15, 517},   // After constant header, before footer
            new[] {15, 519},   // After constant header, to end
            new[] {16, 517},   // After header+nonce, before footer
            new[] {16, 519},   // After header+nonce, to end
            new[] {0, 517},    // Full packet minus footer
            new[] {0, 519},    // Full packet
        };

        foreach (var range in ranges)
        {
            int start = range[0], end = range[1];
            int len = end - start;
            if (len < 8) continue;

            System.Console.WriteLine($"--- Encrypted region: [{start}..{end}) = {len} bytes ({len/8} full blocks, {len%8} remainder) ---");

            var encrypted = new byte[len];
            Array.Copy(packets[0].Data, start, encrypted, 0, len);

            // Double CFB decrypt
            var dec = DoubleCfbDecrypt(cipher, encrypted);
            System.Console.Write($"  Double CFB: {BitConverter.ToString(dec, 0, Math.Min(40, dec.Length))}");
            System.Console.WriteLine();
            CheckAllPatterns(dec, $"dblCFB@{start}");

            // Also try single CFB for comparison
            var singleDec = CfbDecrypt(cipher, encrypted, new byte[8]);
            System.Console.Write($"  Single CFB: {BitConverter.ToString(singleDec, 0, Math.Min(40, singleDec.Length))}");
            System.Console.WriteLine();
            CheckAllPatterns(singleDec, $"sglCFB@{start}");

            // Try double with OFB instead of CFB
            var doubleOfb = DoubleOfbDecrypt(cipher, encrypted);
            CheckAllPatterns(doubleOfb, $"dblOFB@{start}");

            System.Console.WriteLine();
        }

        // ====================================================================
        // CROSS-PACKET COMPARISON with double CFB
        // ====================================================================
        System.Console.WriteLine("=== DOUBLE CFB ON ALL CAPTURED PACKETS ===");
        foreach (var p in packets)
        {
            // Try the most likely range: [15..517) or [16..517)
            foreach (int start in new[] { 8, 15, 16 })
            {
                int len = 517 - start;
                var encrypted = new byte[len];
                Array.Copy(p.Data, start, encrypted, 0, len);
                var dec = DoubleCfbDecrypt(cipher, encrypted);

                byte nonce = p.Data[15];
                System.Console.Write($"  {p.Name} @{start} nonce=0x{nonce:X2}: ");
                System.Console.Write(BitConverter.ToString(dec, 0, Math.Min(24, dec.Length)));

                // Check for ENet command at various offsets within the decrypted data
                bool found = false;
                for (int cmdOff = 0; cmdOff < Math.Min(20, dec.Length - 4); cmdOff++)
                {
                    int cmd = dec[cmdOff] & 0x0F;
                    if (cmd >= 1 && cmd <= 6)
                    {
                        byte ch = dec[cmdOff + 1];
                        if (ch == 0xFF || ch == 0x00 || ch < 0x40)
                        {
                            ushort seq = (ushort)((dec[cmdOff + 2] << 8) | dec[cmdOff + 3]);
                            if (cmd == 2 && cmdOff + 8 < dec.Length)
                            {
                                ushort mtu = (ushort)((dec[cmdOff + 6] << 8) | dec[cmdOff + 7]);
                                if (mtu == 996)
                                {
                                    System.Console.Write($" *** CONNECT MTU=996 @{cmdOff}! ***");
                                    found = true;
                                }
                            }
                        }
                    }
                }
                System.Console.WriteLine();
            }
        }

        // ====================================================================
        // Try RECV packets with double CFB too
        // ====================================================================
        System.Console.WriteLine();
        System.Console.WriteLine("=== RECV PACKETS ANALYSIS ===");
        foreach (var rp in recvPkts)
        {
            System.Console.WriteLine($"\n  {rp.Name} ({rp.Data.Length}B): {BitConverter.ToString(rp.Data, 0, Math.Min(24, rp.Data.Length))}");

            // RECV packets are smaller (48B or 16B), try full double CFB
            if (rp.Data.Length >= 8)
            {
                var dec = DoubleCfbDecrypt(cipher, rp.Data);
                System.Console.Write($"  Double CFB full: {BitConverter.ToString(dec, 0, Math.Min(24, dec.Length))}");
                CheckAllPatterns(dec, "RECV dblCFB");
                System.Console.WriteLine();

                var singleDec = CfbDecrypt(cipher, rp.Data, new byte[8]);
                System.Console.Write($"  Single CFB full: {BitConverter.ToString(singleDec, 0, Math.Min(24, singleDec.Length))}");
                CheckAllPatterns(singleDec, "RECV sglCFB");
                System.Console.WriteLine();
            }
        }

        // ====================================================================
        // Verify with BF_encrypt byte order
        // The Ghidra decompilation shows the function reads/writes in big-endian.
        // But maybe our BlowFish C# implementation uses different byte order?
        // ====================================================================
        System.Console.WriteLine();
        System.Console.WriteLine("=== BLOWFISH BYTE ORDER TEST ===");
        {
            // Standard test: encrypt [00 00 00 00 00 00 00 00]
            var zeros = new byte[8];
            var enc = cipher.EncryptBlock(zeros);
            System.Console.WriteLine($"  Encrypt(zeros)   = {BitConverter.ToString(enc)}");

            // Try swapping 32-bit halves
            var swapped = new byte[8];
            Array.Copy(enc, 4, swapped, 0, 4);
            Array.Copy(enc, 0, swapped, 4, 4);
            System.Console.WriteLine($"  Swapped halves    = {BitConverter.ToString(swapped)}");

            // Try reversing all 8 bytes
            var reversed = enc.Reverse().ToArray();
            System.Console.WriteLine($"  Fully reversed    = {BitConverter.ToString(reversed)}");

            // Try each 32-bit half in LE
            var leHalves = new byte[8];
            leHalves[0] = enc[3]; leHalves[1] = enc[2]; leHalves[2] = enc[1]; leHalves[3] = enc[0];
            leHalves[4] = enc[7]; leHalves[5] = enc[6]; leHalves[6] = enc[5]; leHalves[7] = enc[4];
            System.Console.WriteLine($"  LE halves         = {BitConverter.ToString(leHalves)}");

            // Now try CFB decrypt with byte-swapped keystream
            System.Console.WriteLine();
            System.Console.WriteLine("  Testing CFB with different BF byte orders on packet[8..517]:");
            var pktEnc = new byte[509];
            Array.Copy(packets[0].Data, 8, pktEnc, 0, 509);

            // Standard
            var d1 = CfbDecrypt(cipher, pktEnc, new byte[8]);
            System.Console.WriteLine($"    Standard:    {BitConverter.ToString(d1, 0, 16)}");

            // Swapped halves in keystream
            var d2 = CfbDecryptSwapHalves(cipher, pktEnc, new byte[8]);
            System.Console.WriteLine($"    SwapHalves:  {BitConverter.ToString(d2, 0, 16)}");

            // LE halves in keystream
            var d3 = CfbDecryptLEHalves(cipher, pktEnc, new byte[8]);
            System.Console.WriteLine($"    LEHalves:    {BitConverter.ToString(d3, 0, 16)}");

            // Full reverse in keystream
            var d4 = CfbDecryptReversed(cipher, pktEnc, new byte[8]);
            System.Console.WriteLine($"    Reversed:    {BitConverter.ToString(d4, 0, 16)}");

            // Now double CFB with each variant
            System.Console.WriteLine();
            System.Console.WriteLine("  Double CFB with byte order variants on packet[8..517]:");

            var dd1 = DoubleCfbDecrypt(cipher, pktEnc);
            System.Console.WriteLine($"    Standard:    {BitConverter.ToString(dd1, 0, 16)}");

            var dd2 = DoubleCfbDecryptSwap(cipher, pktEnc);
            System.Console.WriteLine($"    SwapHalves:  {BitConverter.ToString(dd2, 0, 16)}");

            var dd3 = DoubleCfbDecryptLE(cipher, pktEnc);
            System.Console.WriteLine($"    LEHalves:    {BitConverter.ToString(dd3, 0, 16)}");

            // Check all for CONNECT patterns
            CheckAllPatterns(dd1, "dbl-std");
            CheckAllPatterns(dd2, "dbl-swap");
            CheckAllPatterns(dd3, "dbl-LE");
        }

        // Decrypt Riot server's VERIFY_CONNECT response to see the real format
        System.Console.WriteLine("=== RIOT SERVER RESPONSE DECRYPTION ===");
        {
            var riotKey = "jNdWPAc3Vb5AyjoYdkar/g==";
            var riotCipher = BlowFish.FromBase64(riotKey);
            var riotResp = HexToBytes("b2cc6caa8092ade003dc4263fda135da21cbdd3b0eb45076a328cb7bf8a0616d2e4a28822d6385e3b2440080a1ba6c9abd2077359378807a969aa3c42f4deb7f2e2f3fc54c9ae6e82328982b6f5a074eaf7ca425c590a0fa050dccf9fb0a78dd804d02d9964515bf9a074c4c069280");
            System.Console.WriteLine($"  Riot response: {riotResp.Length} bytes");

            // Try single CFB with IV=0
            var riotDec = CfbDecryptWith(riotCipher, riotResp, new byte[8]);
            System.Console.WriteLine($"  CFB decrypt: {BitConverter.ToString(riotDec, 0, Math.Min(48, riotDec.Length))}");

            // Parse as ENet
            uint sess = ReadBE32(riotDec, 0);
            ushort peerRaw = ReadBE16(riotDec, 4);
            bool hasTime = (peerRaw & 0x8000) != 0;
            ushort peer = (ushort)(peerRaw & 0x7FFF);
            int off = hasTime ? 8 : 6;
            System.Console.Write($"  sessID=0x{sess:X8} peer=0x{peer:X4} hasTime={hasTime}");
            if (hasTime) System.Console.Write($" time={ReadBE16(riotDec, 6)}");
            System.Console.WriteLine();

            // Parse commands
            while (off + 4 <= riotDec.Length)
            {
                byte cmdByte = riotDec[off];
                byte ch = riotDec[off + 1];
                ushort seq = ReadBE16(riotDec, off + 2);
                int cmd = cmdByte & 0x0F;
                int flags = (cmdByte >> 4) & 0x0F;
                string[] cmdNames = {"?","ACK","CONNECT","VERIFY_CONNECT","DISCONNECT","PING","SEND_RELIABLE","SEND_UNRELIABLE","SEND_FRAGMENT","SEND_UNSEQUENCED","BW_LIMIT","THROTTLE","SEND_UNRELIABLE_FRAG"};
                string name = cmd < cmdNames.Length ? cmdNames[cmd] : $"?{cmd}";
                System.Console.Write($"  Cmd @{off}: 0x{cmdByte:X2}({name}) ch=0x{ch:X2} seq={seq}");

                if (cmd == 3 && off + 40 <= riotDec.Length) // VERIFY_CONNECT
                {
                    int b = off + 4;
                    System.Console.WriteLine();
                    System.Console.WriteLine($"    outPeer={ReadBE16(riotDec, b)} MTU={ReadBE16(riotDec, b+2)} winSize={ReadBE32(riotDec, b+4)} chanCount={ReadBE32(riotDec, b+8)}");
                    System.Console.WriteLine($"    inBW={ReadBE32(riotDec, b+12)} outBW={ReadBE32(riotDec, b+16)} throttle={ReadBE32(riotDec, b+20)}/{ReadBE32(riotDec, b+24)}/{ReadBE32(riotDec, b+28)}");
                    if (b + 36 <= riotDec.Length) System.Console.WriteLine($"    connID=0x{ReadBE32(riotDec, b+32):X8}");
                    off = b + 36;
                }
                else if (cmd == 6 && off + 6 <= riotDec.Length) // SEND_RELIABLE
                {
                    ushort dataLen = ReadBE16(riotDec, off + 4);
                    System.Console.Write($" len={dataLen}");
                    if (off + 6 + dataLen <= riotDec.Length)
                    {
                        System.Console.Write($" data={BitConverter.ToString(riotDec, off + 6, Math.Min(24, (int)dataLen))}");
                    }
                    System.Console.WriteLine();
                    off += 6 + dataLen;
                }
                else if (cmd == 1 && off + 8 <= riotDec.Length) // ACK
                {
                    ushort ackSeq = ReadBE16(riotDec, off + 4);
                    ushort ackTime = ReadBE16(riotDec, off + 6);
                    System.Console.Write($" ackSeq={ackSeq} ackTime={ackTime}");
                    System.Console.WriteLine();
                    off += 8;
                }
                else
                {
                    System.Console.WriteLine();
                    break;
                }
            }
            System.Console.WriteLine($"  Remaining bytes from {off}: {BitConverter.ToString(riotDec, off, Math.Min(24, riotDec.Length - off))}");
        }
        System.Console.WriteLine();

        // Verify P-box and test key byte orderings
        VerifyPBox();

        // Try LE key byte ordering
        System.Console.WriteLine("\n=== KEY BYTE ORDER TESTS ===");
        {
            var ctxPath = Path.Combine(captureDir, "CRYPTO_CTX_000001D56CB567C0.bin");
            var ctx = File.ReadAllBytes(ctxPath);
            uint targetP0 = ReadBE32(ctx, 16); // 0x7628CDBB

            // Original key
            TestKeyOrder(keyBytes, "Original", targetP0);

            // Reverse all bytes
            var revAll = keyBytes.Reverse().ToArray();
            TestKeyOrder(revAll, "Reversed all", targetP0);

            // Swap each 4-byte group to LE
            var leGroups = new byte[keyBytes.Length];
            for (int i = 0; i < keyBytes.Length; i += 4)
            {
                leGroups[i] = keyBytes[i + 3];
                leGroups[i + 1] = keyBytes[i + 2];
                leGroups[i + 2] = keyBytes[i + 1];
                leGroups[i + 3] = keyBytes[i];
            }
            TestKeyOrder(leGroups, "LE 4-byte groups", targetP0);

            // Swap each 2-byte group
            var le2 = new byte[keyBytes.Length];
            for (int i = 0; i < keyBytes.Length; i += 2)
            {
                le2[i] = keyBytes[i + 1];
                le2[i + 1] = keyBytes[i];
            }
            TestKeyOrder(le2, "LE 2-byte groups", targetP0);

            // Try just the key string as ASCII bytes (not base64 decoded)
            var asciiKey = System.Text.Encoding.ASCII.GetBytes("jNdWPAc3Vb5AyjoYdkar/g==");
            TestKeyOrder(asciiKey, "ASCII key string", targetP0);

            // Try the key as hex string bytes
            var hexKey = System.Text.Encoding.ASCII.GetBytes(BitConverter.ToString(keyBytes).Replace("-", ""));
            if (hexKey.Length <= 56) // max BF key
                TestKeyOrder(hexKey, "Hex key string", targetP0);

            // What if gameconfig.json has a different key?
            var configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "gameconfig.json");
            if (File.Exists(configPath))
            {
                var configJson = File.ReadAllText(configPath);
                System.Console.WriteLine($"\n  Config file BlowfishKey search:");
                var match = System.Text.RegularExpressions.Regex.Match(configJson, "\"BlowfishKey\"\\s*:\\s*\"([^\"]+)\"");
                if (match.Success)
                {
                    var configKey = match.Groups[1].Value;
                    System.Console.WriteLine($"  Config key: {configKey}");
                    var configKeyBytes = Convert.FromBase64String(configKey);
                    System.Console.WriteLine($"  Config bytes: {BitConverter.ToString(configKeyBytes)}");
                    TestKeyOrder(configKeyBytes, "Config key", targetP0);
                }
            }
        }

        // ====================================================================
        // GAME MODE 2 EXACT REIMPLEMENTATION
        // Directly translate Ghidra decompilation to C#
        // ====================================================================
        System.Console.WriteLine();
        System.Console.WriteLine("=== EXACT GHIDRA MODE 2 REIMPLEMENTATION ===");
        {
            var pktEnc = new byte[509];
            Array.Copy(packets[0].Data, 8, pktEnc, 0, 509);

            // Do the exact mode 2 operation as decompiled
            var dec = ExactMode2Decrypt(cipher, pktEnc);
            System.Console.Write($"  Single exact mode2: {BitConverter.ToString(dec, 0, Math.Min(32, dec.Length))}");
            CheckAllPatterns(dec, "exact-mode2");
            System.Console.WriteLine();

            // Double exact mode2 with reversal
            dec = ExactDoubleMode2Decrypt(cipher, pktEnc);
            System.Console.Write($"  Double exact mode2: {BitConverter.ToString(dec, 0, Math.Min(32, dec.Length))}");
            CheckAllPatterns(dec, "exact-dbl-mode2");
            System.Console.WriteLine();

            // Also try on different offsets
            foreach (int off in new[] { 15, 16 })
            {
                var enc2 = new byte[517 - off];
                Array.Copy(packets[0].Data, off, enc2, 0, enc2.Length);
                dec = ExactDoubleMode2Decrypt(cipher, enc2);
                System.Console.Write($"  Double exact @{off}: {BitConverter.ToString(dec, 0, Math.Min(32, dec.Length))}");
                CheckAllPatterns(dec, $"exact-dbl@{off}");
                System.Console.WriteLine();
            }
        }
    }

    // =====================================================================
    // EXACT Ghidra mode 2 reimplementation
    // =====================================================================

    /// <summary>
    /// Exact reimplementation of FUN_1410f41e0 mode=2.
    /// The game's encryption is: BF_encrypt(IV) -> XOR with data -> feedback = output
    /// To decrypt received data, we need: BF_encrypt(IV) -> XOR with data -> feedback = input (before XOR)
    /// </summary>
    static byte[] ExactMode2Decrypt(BlowFish cipher, byte[] data)
    {
        var result = (byte[])data.Clone();
        int numBlocks = result.Length / 8;

        // IV starts at zero (confirmed from crypto context capture)
        uint ivLeft = 0, ivRight = 0;

        for (int block = 0; block < numBlocks; block++)
        {
            int off = block * 8;

            // BF_encrypt the IV (same as game's FUN_1410f3d90)
            byte[] ivBytes = new byte[8];
            WriteBE32(ivBytes, 0, ivLeft);
            WriteBE32(ivBytes, 4, ivRight);
            byte[] keystream = cipher.EncryptBlock(ivBytes);
            uint ksLeft = ReadBE32(keystream, 0);
            uint ksRight = ReadBE32(keystream, 4);

            // Read data as big-endian 32-bit pairs (as per Ghidra decompilation)
            uint dataLeft = ReadBE32(result, off);
            uint dataRight = ReadBE32(result, off + 4);

            // Save input for feedback (for decryption, feedback = ciphertext = input)
            ivLeft = dataLeft;
            ivRight = dataRight;

            // XOR with keystream
            uint outLeft = dataLeft ^ ksLeft;
            uint outRight = dataRight ^ ksRight;

            // Write back in big-endian
            WriteBE32(result, off, outLeft);
            WriteBE32(result, off + 4, outRight);
        }

        return result;
    }

    /// <summary>
    /// Same as ExactMode2Decrypt but using ENCRYPTION feedback (output fed back, not input).
    /// This is what the game's mode=2 actually does per the decompilation.
    /// To "undo" encryption, we actually need decryption feedback.
    /// But let's test encryption feedback too to see what happens.
    /// </summary>
    static byte[] ExactMode2EncryptFeedback(BlowFish cipher, byte[] data)
    {
        var result = (byte[])data.Clone();
        int numBlocks = result.Length / 8;
        uint ivLeft = 0, ivRight = 0;

        for (int block = 0; block < numBlocks; block++)
        {
            int off = block * 8;
            byte[] ivBytes = new byte[8];
            WriteBE32(ivBytes, 0, ivLeft);
            WriteBE32(ivBytes, 4, ivRight);
            byte[] keystream = cipher.EncryptBlock(ivBytes);
            uint ksLeft = ReadBE32(keystream, 0);
            uint ksRight = ReadBE32(keystream, 4);

            uint dataLeft = ReadBE32(result, off);
            uint dataRight = ReadBE32(result, off + 4);

            uint outLeft = dataLeft ^ ksLeft;
            uint outRight = dataRight ^ ksRight;

            // Feedback = output (encryption mode)
            ivLeft = outLeft;
            ivRight = outRight;

            WriteBE32(result, off, outLeft);
            WriteBE32(result, off + 4, outRight);
        }

        return result;
    }

    /// <summary>
    /// Full double-pass decryption matching the Ghidra decompilation.
    /// Game encrypts: mode2(data) -> reverse -> mode2(data)
    /// We decrypt: mode2_decrypt(data) -> reverse -> mode2_decrypt(data)
    /// </summary>
    static byte[] ExactDoubleMode2Decrypt(BlowFish cipher, byte[] data)
    {
        // Pass 1: undo the second CFB encrypt
        var result = ExactMode2Decrypt(cipher, data);

        // Reverse the buffer (undo the byte reversal)
        int processedLen = (result.Length / 8) * 8;
        Array.Reverse(result, 0, processedLen);

        // Pass 2: undo the first CFB encrypt
        result = ExactMode2Decrypt(cipher, result);

        return result;
    }

    // =====================================================================
    // CFB variants
    // =====================================================================

    static byte[] DoubleCfbDecrypt(BlowFish cipher, byte[] data)
    {
        // Pass 1: CFB decrypt (undo second encryption pass)
        var result = CfbDecrypt(cipher, data, new byte[8]);
        // Reverse
        int processed = (result.Length / 8) * 8;
        Array.Reverse(result, 0, processed);
        // Pass 2: CFB decrypt (undo first encryption pass)
        result = CfbDecrypt(cipher, result, new byte[8]);
        return result;
    }

    static byte[] DoubleOfbDecrypt(BlowFish cipher, byte[] data)
    {
        var result = OfbProcess(cipher, data, new byte[8]);
        int processed = (result.Length / 8) * 8;
        Array.Reverse(result, 0, processed);
        result = OfbProcess(cipher, result, new byte[8]);
        return result;
    }

    static byte[] DoubleCfbDecryptSwap(BlowFish cipher, byte[] data)
    {
        var result = CfbDecryptSwapHalves(cipher, data, new byte[8]);
        int processed = (result.Length / 8) * 8;
        Array.Reverse(result, 0, processed);
        result = CfbDecryptSwapHalves(cipher, result, new byte[8]);
        return result;
    }

    static byte[] DoubleCfbDecryptLE(BlowFish cipher, byte[] data)
    {
        var result = CfbDecryptLEHalves(cipher, data, new byte[8]);
        int processed = (result.Length / 8) * 8;
        Array.Reverse(result, 0, processed);
        result = CfbDecryptLEHalves(cipher, result, new byte[8]);
        return result;
    }

    // Standard CFB decrypt
    static byte[] CfbDecrypt(BlowFish cipher, byte[] data, byte[] iv)
    {
        var result = new byte[data.Length];
        var feedback = (byte[])iv.Clone();
        for (int i = 0; i < data.Length - 7; i += 8)
        {
            var ks = cipher.EncryptBlock(feedback);
            Array.Copy(data, i, feedback, 0, 8); // feedback = ciphertext (input)
            for (int j = 0; j < 8; j++)
                result[i + j] = (byte)(data[i + j] ^ ks[j]);
        }
        // Copy remaining bytes unprocessed
        int rem = data.Length % 8;
        if (rem > 0) Array.Copy(data, data.Length - rem, result, data.Length - rem, rem);
        return result;
    }

    static byte[] CfbDecryptSwapHalves(BlowFish cipher, byte[] data, byte[] iv)
    {
        var result = new byte[data.Length];
        var feedback = (byte[])iv.Clone();
        for (int i = 0; i < data.Length - 7; i += 8)
        {
            var ks = cipher.EncryptBlock(feedback);
            // Swap 32-bit halves of keystream
            var swapped = new byte[8];
            Array.Copy(ks, 4, swapped, 0, 4);
            Array.Copy(ks, 0, swapped, 4, 4);
            Array.Copy(data, i, feedback, 0, 8);
            for (int j = 0; j < 8; j++)
                result[i + j] = (byte)(data[i + j] ^ swapped[j]);
        }
        int rem = data.Length % 8;
        if (rem > 0) Array.Copy(data, data.Length - rem, result, data.Length - rem, rem);
        return result;
    }

    static byte[] CfbDecryptLEHalves(BlowFish cipher, byte[] data, byte[] iv)
    {
        var result = new byte[data.Length];
        var feedback = (byte[])iv.Clone();
        for (int i = 0; i < data.Length - 7; i += 8)
        {
            var ks = cipher.EncryptBlock(feedback);
            // Convert each 32-bit half from BE to LE
            var le = new byte[8];
            le[0] = ks[3]; le[1] = ks[2]; le[2] = ks[1]; le[3] = ks[0];
            le[4] = ks[7]; le[5] = ks[6]; le[6] = ks[5]; le[7] = ks[4];
            Array.Copy(data, i, feedback, 0, 8);
            for (int j = 0; j < 8; j++)
                result[i + j] = (byte)(data[i + j] ^ le[j]);
        }
        int rem = data.Length % 8;
        if (rem > 0) Array.Copy(data, data.Length - rem, result, data.Length - rem, rem);
        return result;
    }

    static byte[] CfbDecryptReversed(BlowFish cipher, byte[] data, byte[] iv)
    {
        var result = new byte[data.Length];
        var feedback = (byte[])iv.Clone();
        for (int i = 0; i < data.Length - 7; i += 8)
        {
            var ks = cipher.EncryptBlock(feedback);
            var rev = ks.Reverse().ToArray();
            Array.Copy(data, i, feedback, 0, 8);
            for (int j = 0; j < 8; j++)
                result[i + j] = (byte)(data[i + j] ^ rev[j]);
        }
        int rem = data.Length % 8;
        if (rem > 0) Array.Copy(data, data.Length - rem, result, data.Length - rem, rem);
        return result;
    }

    static byte[] OfbProcess(BlowFish cipher, byte[] data, byte[] iv)
    {
        var result = new byte[data.Length];
        var feedback = (byte[])iv.Clone();
        for (int i = 0; i < data.Length - 7; i += 8)
        {
            feedback = cipher.EncryptBlock(feedback);
            for (int j = 0; j < 8; j++)
                result[i + j] = (byte)(data[i + j] ^ feedback[j]);
        }
        int rem = data.Length % 8;
        if (rem > 0) Array.Copy(data, data.Length - rem, result, data.Length - rem, rem);
        return result;
    }

    // =====================================================================
    // Pattern detection
    // =====================================================================

    static void CheckAllPatterns(byte[] dec, string label)
    {
        // Look for ENet CONNECT with MTU=996 anywhere in first 64 bytes
        for (int i = 0; i < Math.Min(64, dec.Length - 8); i++)
        {
            int cmd = dec[i] & 0x0F;
            if (cmd == 2) // CONNECT
            {
                byte ch = dec[i + 1];
                ushort seq = (ushort)((dec[i + 2] << 8) | dec[i + 3]);
                // Check MTU at expected offset (cmd+4 bytes header + 2 bytes peerID = i+6)
                for (int moff = i + 4; moff < Math.Min(i + 12, dec.Length - 1); moff++)
                {
                    ushort mtuBE = (ushort)((dec[moff] << 8) | dec[moff + 1]);
                    ushort mtuLE = (ushort)(dec[moff] | (dec[moff + 1] << 8));
                    if (mtuBE == 996)
                        System.Console.WriteLine($"  *** [{label}] CONNECT MTU=996(BE) @cmd={i} mtu@{moff} ch=0x{ch:X2} seq={seq} ***");
                    if (mtuLE == 996)
                        System.Console.WriteLine($"  *** [{label}] CONNECT MTU=996(LE) @cmd={i} mtu@{moff} ch=0x{ch:X2} seq={seq} ***");
                }
            }

            // Also look for the KeyCheck opcode (0x00 0x2D) which is sent early in the handshake
            if (i + 1 < dec.Length && dec[i] == 0x00 && dec[i + 1] == 0x2D)
            {
                System.Console.WriteLine($"  *** [{label}] KeyCheck opcode 0x002D @{i} ***");
            }
        }

        // Check for recognizable session IDs in the decrypted data
        // Our expected SessionID (DEADBEEF) or similar
        for (int i = 0; i < Math.Min(32, dec.Length - 4); i++)
        {
            uint valBE = ReadBE32(dec, i);
            uint valLE = (uint)(dec[i] | (dec[i+1]<<8) | (dec[i+2]<<16) | (dec[i+3]<<24));
            if (valBE == 0xDEADBEEF || valLE == 0xDEADBEEF)
                System.Console.WriteLine($"  *** [{label}] DEADBEEF @{i} ({(valBE == 0xDEADBEEF ? "BE" : "LE")}) ***");
        }
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    static byte[] CfbDecryptWith(BlowFish cipher, byte[] data, byte[] iv)
    {
        var result = new byte[data.Length];
        var feedback = (byte[])iv.Clone();
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

    static byte[] HexToBytes(string hex)
    {
        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return bytes;
    }

    static ushort ReadBE16(byte[] b, int o) => (ushort)((b[o] << 8) | b[o + 1]);
    static uint ReadBE32(byte[] b, int o) => (uint)((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]);
    static void WriteBE32(byte[] b, int o, uint v) { b[o] = (byte)(v >> 24); b[o + 1] = (byte)(v >> 16); b[o + 2] = (byte)(v >> 8); b[o + 3] = (byte)v; }

    static void TestKeyOrder(byte[] key, string label, uint targetP0)
    {
        try
        {
            var bf = new BlowFish(key);
            System.Console.Write($"  {label,-22}: P[0]=0x{bf.PBox[0]:X8}");
            if (bf.PBox[0] == targetP0)
                System.Console.Write(" *** MATCH! ***");
            System.Console.WriteLine();
        }
        catch (Exception ex)
        {
            System.Console.WriteLine($"  {label,-22}: ERROR {ex.Message}");
        }
    }

    /// <summary>
    /// Verify our P-box matches the captured crypto context byte-for-byte.
    /// </summary>
    public static void VerifyPBox()
    {
        var keyBytes = Convert.FromBase64String(BlowfishKeyB64);
        var cipher = new BlowFish(keyBytes);
        var ctxFile = @"D:\LeagueOfLegendsV2\client-private\Game\nethook_logs\CRYPTO_CTX_000001D56CB567C0.bin";
        var ctx = File.ReadAllBytes(ctxFile);

        System.Console.WriteLine("=== P-BOX VERIFICATION ===");
        bool allMatch = true;
        for (int i = 0; i < 18; i++)
        {
            uint ourP = cipher.PBox[i];
            int off = 16 + i * 4;
            uint capturedP = ReadBE32(ctx, off);
            bool match = ourP == capturedP;
            if (!match) allMatch = false;
            System.Console.WriteLine($"  P[{i:D2}]: ours=0x{ourP:X8} captured=0x{capturedP:X8} {(match ? "OK" : "MISMATCH!")}");
        }
        System.Console.WriteLine($"  All P-box entries match: {allMatch}");

        // Also verify first few S-box entries
        System.Console.WriteLine("\n  S-box[0] first 4 entries:");
        for (int i = 0; i < 4; i++)
        {
            uint ourS = 0u; // can't access _sbox easily
            int sboxOff = 16 + 72 + i * 4; // After header(16) + P-box(72)
            uint capturedS = ReadBE32(ctx, sboxOff);
            System.Console.WriteLine($"    S[0][{i}] captured=0x{capturedS:X8} @offset={sboxOff}");
        }
    }
}
