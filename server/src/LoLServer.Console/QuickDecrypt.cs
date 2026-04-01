using System;
using System.IO;
using LoLServer.Core.Network;

namespace LoLServer.Console;

public static class QuickDecrypt
{
    public static void Run()
    {
        var cipher = BlowFish.FromBase64("17BLOhi6KZsTtldTsizvHg==");

        // S-BOX VERIFICATION against captured crypto context
        uint[] expectedS0 = { 0x52D436FF, 0xA5613C01, 0xA88AA146, 0x38319B56, 0x40C98634 };
        System.Console.WriteLine("=== S-BOX VERIFICATION ===");
        bool allMatch = true;
        for (int i = 0; i < 5; i++)
        {
            uint ours = cipher.SBox[0, i];
            bool m = ours == expectedS0[i];
            if (!m) allMatch = false;
            System.Console.WriteLine($"  S[0][{i}]: ours=0x{ours:X8} ctx=0x{expectedS0[i]:X8} {(m ? "OK" : "MISMATCH!")}");
        }
        System.Console.WriteLine($"  ALL S-BOX MATCH: {allMatch}");

        // Test BF_encrypt of non-zero input
        var testBlock = new byte[] { 0xED, 0xE3, 0x6B, 0x43, 0xF9, 0xED, 0x26, 0xB1 };
        var encTest = cipher.EncryptBlock(testBlock);
        System.Console.WriteLine($"  BF_encrypt(first ciphertext block) = {BitConverter.ToString(encTest)}");
        System.Console.WriteLine();

        // === CRITICAL TEST: Double CFB encrypt/decrypt roundtrip on CLIENT DATA ===
        System.Console.WriteLine("=== ROUNDTRIP TEST ON ACTUAL CLIENT DATA ===");
        {
            var testFile = @"D:\LeagueOfLegendsV2\client-private\Game\nethook_logs\SEND_0001_519B.bin";
            if (File.Exists(testFile))
            {
                var pkt = File.ReadAllBytes(testFile);
                // Extract encrypted data: bytes 12-518 (skip LNPBlob+token)
                var encrypted = new byte[pkt.Length - 12];
                Array.Copy(pkt, 12, encrypted, 0, encrypted.Length);
                System.Console.WriteLine($"  Encrypted data: {encrypted.Length}B, first={BitConverter.ToString(encrypted, 0, 8)}");

                // Double CFB decrypt
                var decrypted = DoubleCfbDecrypt(cipher, encrypted);
                System.Console.WriteLine($"  Decrypted: {BitConverter.ToString(decrypted, 0, Math.Min(16, decrypted.Length))}");

                // Double CFB RE-encrypt
                var reEncrypted = DoubleCfbEncrypt(cipher, decrypted);
                System.Console.WriteLine($"  Re-encrypted: {BitConverter.ToString(reEncrypted, 0, Math.Min(8, reEncrypted.Length))}");

                // Compare
                bool match = true;
                int firstDiff = -1;
                for (int i = 0; i < encrypted.Length; i++)
                {
                    if (encrypted[i] != reEncrypted[i])
                    {
                        if (firstDiff == -1) firstDiff = i;
                        match = false;
                    }
                }
                System.Console.WriteLine($"  ROUNDTRIP MATCH: {match}");
                if (!match)
                    System.Console.WriteLine($"  First difference at byte {firstDiff}: orig=0x{encrypted[firstDiff]:X2} re=0x{reEncrypted[firstDiff]:X2}");

                // Now verify CRC nonce computation
                if (decrypted.Length >= 7)
                {
                    ushort peerID = (ushort)(decrypted[0] | (decrypted[1] << 8));
                    uint nonce = (uint)((decrypted[2] << 24) | (decrypted[3] << 16) | (decrypted[4] << 8) | decrypted[5]);
                    byte flags = decrypted[6];
                    byte cmdType = (byte)(flags & 0x7F);
                    bool hasTS = (flags & 0x80) != 0;
                    int payloadOff = 7 + (hasTS ? 8 : 0);
                    byte[] payload = new byte[decrypted.Length - payloadOff];
                    Array.Copy(decrypted, payloadOff, payload, 0, payload.Length);

                    System.Console.WriteLine($"\n  Parsed: peerID=0x{peerID:X4} nonce=0x{nonce:X8} flags=0x{flags:X2} cmd={cmdType} hasTS={hasTS}");
                    System.Console.WriteLine($"  Payload ({payload.Length}B): {BitConverter.ToString(payload, 0, Math.Min(16, payload.Length))}");

                    // Compute CRC using our algorithm and compare
                    byte peerLo = (byte)(peerID & 0xFF);
                    byte peerHi = (byte)((peerID >> 8) & 0xFF);
                    byte[] localRes10 = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                    byte[] timestamp = new byte[8]; // zeros if no timestamp

                    if (hasTS && decrypted.Length >= 15)
                        Array.Copy(decrypted, 7, timestamp, 0, 8);

                    // CRC init: (peerLo | 0xFFFFFF00) ^ 0xB1F740B4
                    uint crc = ((uint)peerLo | 0xFFFFFF00u) ^ 0xB1F740B4u;
                    // Process peerHi
                    crc = CrcByteMPEG2(crc, peerHi);
                    // Process localRes10
                    for (int i = 0; i < 8; i++) crc = CrcByteMPEG2(crc, localRes10[i]);
                    // Process timestamp
                    for (int i = 0; i < 8; i++) crc = CrcByteMPEG2(crc, timestamp[i]);
                    // Process payload
                    for (int i = 0; i < payload.Length; i++) crc = CrcByteMPEG2(crc, payload[i]);
                    uint computedNonce = ~crc;

                    System.Console.WriteLine($"  CRC check: computed=0x{computedNonce:X8} expected=0x{nonce:X8} {(computedNonce == nonce ? "MATCH!" : "MISMATCH!")}");

                    // Also try without localRes10 = 1 (try 0)
                    byte[] localRes0 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                    crc = ((uint)peerLo | 0xFFFFFF00u) ^ 0xB1F740B4u;
                    crc = CrcByteMPEG2(crc, peerHi);
                    for (int i = 0; i < 8; i++) crc = CrcByteMPEG2(crc, localRes0[i]);
                    for (int i = 0; i < 8; i++) crc = CrcByteMPEG2(crc, timestamp[i]);
                    for (int i = 0; i < payload.Length; i++) crc = CrcByteMPEG2(crc, payload[i]);
                    System.Console.WriteLine($"  CRC (localRes=0): 0x{~crc:X8} {(~crc == nonce ? "MATCH!" : "no")}");
                }
            }
            else
            {
                System.Console.WriteLine("  No SEND_0001_519B.bin found");
            }
        }
        System.Console.WriteLine();

        var logDir = @"D:\LeagueOfLegendsV2\client-private\Game\nethook_logs";

        // Find all SEND packets
        foreach (var f in Directory.GetFiles(logDir, "SEND_*.bin"))
        {
            var data = File.ReadAllBytes(f);
            var name = Path.GetFileName(f);
            System.Console.WriteLine($"\n=== {name} ({data.Length}B) ===");

            // Skip LNPBlob (8 bytes) + token (4 bytes) = 12 bytes
            if (data.Length <= 12) continue;
            var enc = new byte[data.Length - 12];
            Array.Copy(data, 12, enc, 0, enc.Length);
            // Also keep the full after-LNPBlob for comparison
            var encFull = new byte[data.Length - 8];
            Array.Copy(data, 8, encFull, 0, encFull.Length);

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
        Array.Reverse(result);  // reverse ALL bytes (matching game)
        result = CfbDecrypt(cipher, result);
        return result;
    }

    static byte[] DoubleCfbEncrypt(BlowFish cipher, byte[] data)
    {
        var result = CfbEncryptFwd(cipher, data);
        Array.Reverse(result);  // reverse ALL bytes
        result = CfbEncryptFwd(cipher, result);
        return result;
    }

    static uint CrcByteMPEG2(uint crc, byte b)
    {
        crc = ((crc << 8) | b) ^ CrcTableMPEG2[crc >> 24];
        return crc;
    }
    static readonly uint[] CrcTableMPEG2 = GenCrcTable();
    static uint[] GenCrcTable()
    {
        var t = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint c = i << 24;
            for (int j = 0; j < 8; j++)
                c = (c & 0x80000000) != 0 ? (c << 1) ^ 0x04C11DB7u : c << 1;
            t[i] = c;
        }
        return t;
    }

    static byte[] CfbEncryptFwd(BlowFish cipher, byte[] data)
    {
        var result = new byte[data.Length];
        var feedback = new byte[8];
        for (int i = 0; i < data.Length; i += 8)
        {
            var ks = cipher.EncryptBlock(feedback);
            int blockLen = Math.Min(8, data.Length - i);
            for (int j = 0; j < blockLen; j++)
                result[i + j] = (byte)(data[i + j] ^ ks[j]);
            Array.Copy(result, i, feedback, 0, blockLen);
            if (blockLen < 8) Array.Clear(feedback, blockLen, 8 - blockLen);
        }
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
// Additional test at end of file

public static class SBoxCheck {
    public static void Verify() {
        var cipher = LoLServer.Core.Network.BlowFish.FromBase64("17BLOhi6KZsTtldTsizvHg==");
        // Expected from captured context (LE uint32):
        uint[] expectedS0 = { 0x52D436FF, 0xA5613C01, 0xA88AA146, 0x38319B56, 0x40C98634 };

        System.Console.WriteLine("=== S-BOX VERIFICATION ===");
        for (int i = 0; i < 5; i++) {
            uint ours = cipher.SBox[0, i];
            bool match = ours == expectedS0[i];
            System.Console.WriteLine($"  S[0][{i}]: ours=0x{ours:X8} ctx=0x{expectedS0[i]:X8} {(match ? "OK" : "MISMATCH!")}");
        }

        // Also test BF_encrypt of a non-zero value
        var testBlock = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        var encrypted = cipher.EncryptBlock(testBlock);
        System.Console.WriteLine($"\n  BF_encrypt(01020304 05060708) = {BitConverter.ToString(encrypted)}");
    }
}
