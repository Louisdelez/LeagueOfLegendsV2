using System;
using LoLServer.Core.Network;

namespace LoLServer.Console;

public static class CryptoAnalysis
{
    public static void Run()
    {
        var privateKey = "17BLOhi6KZsTtldTsizvHg==";
        var pc = BlowFish.FromBase64(privateKey);
        var zeros = new byte[8];

        var encZeros = pc.Encrypt(zeros);
        var decZeros = pc.Decrypt(zeros);
        System.Console.WriteLine($"Encrypt(zeros): {H(encZeros)}");
        System.Console.WriteLine($"Decrypt(zeros): {H(decZeros)}");
        System.Console.WriteLine();

        // Packet data from SEND_0001 (nonce=7F) and SEND_0002 (nonce=63)
        byte n1 = 0x7F, n2 = 0x63;
        var ct1 = HB("AAB1E0251537A80A27A9CD3D23E0BC09");
        var ct2 = HB("4DFFC3867E1E6A31E9C318F03F2A2021");

        var xorCT = XOR(ct1, ct2);
        System.Console.WriteLine($"CT1[16:31] XOR CT2[16:31]: {H(xorCT)}");

        // Test OFB/CTR IV constructions
        string[] ivNames = { "[nonce,0..0]", "[0..0,nonce]", "[nonce*8]" };
        byte[][] iv1s = {
            new byte[] { n1, 0, 0, 0, 0, 0, 0, 0 },
            new byte[] { 0, 0, 0, 0, 0, 0, 0, n1 },
            new byte[] { n1, n1, n1, n1, n1, n1, n1, n1 }
        };
        byte[][] iv2s = {
            new byte[] { n2, 0, 0, 0, 0, 0, 0, 0 },
            new byte[] { 0, 0, 0, 0, 0, 0, 0, n2 },
            new byte[] { n2, n2, n2, n2, n2, n2, n2, n2 }
        };

        for (int t = 0; t < ivNames.Length; t++)
        {
            var k1 = pc.Encrypt(iv1s[t]);
            var k2 = pc.Encrypt(iv2s[t]);
            var xk = XOR(k1, k2);
            bool match = Same(xk, xorCT, 8);
            System.Console.WriteLine($"OFB IV={ivNames[t]}: K1^K2={H(xk, 8)} {(match ? "<<< MATCH!" : "")}");
        }

        System.Console.WriteLine();
        System.Console.WriteLine("=== Full ECB decrypt of bytes [0-31] (pkt1, nonce=7F) ===");
        var fullPkt1 = HB("0000000000000000EDE36B43F9ED267FAAB1E0251537A80A27A9CD3D23E0BC09");
        var fullDec = pc.Decrypt(fullPkt1);
        System.Console.WriteLine($"Decrypt[0:7]  = {H(fullDec, 8, 0)}");
        System.Console.WriteLine($"Decrypt[8:15] = {H(fullDec, 8, 8)}");
        System.Console.WriteLine($"Decrypt[16:23]= {H(fullDec, 8, 16)}");
        System.Console.WriteLine($"Decrypt[24:31]= {H(fullDec, 8, 24)}");

        // Parse decrypted [8:15] as ENet header (Season 8)
        byte sess = fullDec[8];
        byte peerFlags = fullDec[9];
        int peerId = peerFlags & 0x7F;
        bool hasST = (peerFlags & 0x80) != 0;
        System.Console.WriteLine($"  @8 ENet: sess=0x{sess:X2} peer=0x{peerId:X2} sentTime={hasST}");
        if (hasST)
        {
            System.Console.WriteLine($"  @10 TimeSent: 0x{fullDec[10]:X2}{fullDec[11]:X2}");
            System.Console.WriteLine($"  @12 Cmd: 0x{fullDec[12]:X2} (type={fullDec[12] & 0xF}) Ch=0x{fullDec[13]:X2} Seq=0x{fullDec[14]:X2}{fullDec[15]:X2}");
        }
        else
        {
            System.Console.WriteLine($"  @10 Cmd: 0x{fullDec[10]:X2} (type={fullDec[10] & 0xF}) Ch=0x{fullDec[11]:X2} Seq=0x{fullDec[12]:X2}{fullDec[13]:X2}");
        }

        // Parse [16:23] as CONNECT body
        System.Console.WriteLine($"  @16 CONNECT body: outPeerID=0x{fullDec[16]:X2} pad=0x{fullDec[17]:X2} MTU=0x{fullDec[18]:X2}{fullDec[19]:X2}");
        System.Console.WriteLine($"  @20 Window=0x{fullDec[20]:X2}{fullDec[21]:X2}{fullDec[22]:X2}{fullDec[23]:X2}");

        System.Console.WriteLine();
        System.Console.WriteLine("=== Try: Decrypt bytes [8:55] of packet (should be full ENet header + CONNECT) ===");
        var pkt1Full = HB("0000000000000000EDE36B43F9ED267FAAB1E0251537A80A27A9CD3D23E0BC09C1DBCF009EA5C4E2FC18E753D9E5C91D1CC55A66A5F3C22C");
        var decFull = pc.Decrypt(pkt1Full);
        System.Console.WriteLine($"Dec[8-55]: {H(decFull, 48, 8)}");

        // Parse
        System.Console.WriteLine();
        System.Console.WriteLine("=== Also check bytes 8-15 across multiple packets (constant!) ===");
        System.Console.WriteLine("All packets have bytes[8:14] = ED-E3-6B-43-F9-ED-26");
        var constBlock = HB("EDE36B43F9ED2600");
        var decConst = pc.Decrypt(constBlock);
        System.Console.WriteLine($"Decrypt(ED-E3-6B-43-F9-ED-26-00): {H(decConst)}");

        // What if ED-E3-6B-43 = Decrypt(zeros) first 4 bytes?
        System.Console.WriteLine($"Decrypt(zeros)[0:3] = {H(decZeros, 4, 0)}");
        System.Console.WriteLine($"Bytes 8-11 in packet = ED-E3-6B-43");
        System.Console.WriteLine($"Match? {(decZeros[0] == 0xED && decZeros[1] == 0xE3 && decZeros[2] == 0x6B && decZeros[3] == 0x43 ? "YES" : "NO")}");

        if (decZeros[0] == 0xED)
        {
            System.Console.WriteLine();
            System.Console.WriteLine("*** FOUND: bytes[8:11] = Decrypt(zeros)[0:4] ***");
            System.Console.WriteLine("*** And bytes[12:14] = Encrypt(zeros)[0:3] ***");
            System.Console.WriteLine("*** bytes[15] = nonce ***");
            System.Console.WriteLine("*** So header = [8B checksum][4B Decrypt(zeros)][3B Encrypt(zeros)][1B nonce] ***");
        }

        // Now the real key question: what is Decrypt(zeros) with real game key?
        var realKey = "jNdWPAc3Vb5AyjoYdkar/g==";
        var rc = BlowFish.FromBase64(realKey);
        var realEncZ = rc.Encrypt(zeros);
        var realDecZ = rc.Decrypt(zeros);
        System.Console.WriteLine();
        System.Console.WriteLine($"Real game key:");
        System.Console.WriteLine($"  Encrypt(zeros): {H(realEncZ)}");
        System.Console.WriteLine($"  Decrypt(zeros): {H(realDecZ)}");
        System.Console.WriteLine($"  Real pkt bytes[8:11] = D5-B2-6E-6D");
        System.Console.WriteLine($"  Decrypt(zeros)[0:4]  = {H(realDecZ, 4, 0)}");
        System.Console.WriteLine($"  Match? {(realDecZ[0] == 0xD5 && realDecZ[1] == 0xB2 && realDecZ[2] == 0x6E && realDecZ[3] == 0x6D ? "YES" : "NO")}");

        // Deeper investigation: what IS ED-E3-6B-43?
        System.Console.WriteLine();
        System.Console.WriteLine("=== What is ED-E3-6B-43 (bytes 8-11 of private packets)? ===");

        // Test: Encrypt(Encrypt(zeros)) etc
        var enc2 = pc.Encrypt(encZeros);
        var enc3 = pc.Encrypt(enc2);
        System.Console.WriteLine($"Encrypt(Encrypt(zeros)): {H(enc2)}");
        System.Console.WriteLine($"Encrypt^3(zeros):        {H(enc3)}");

        // Test: CRC32 of something?
        // Test: HMAC with key?
        // Test: Decrypt(Encrypt(zeros)) should = zeros
        System.Console.WriteLine($"Decrypt(Encrypt(zeros)): {H(pc.Decrypt(encZeros))} (should be zeros)");

        // Test: what Encrypts to ED-E3-6B-43-XX-XX-XX-XX?
        // i.e., Decrypt(ED-E3-6B-43-...) for various suffix bytes
        System.Console.WriteLine();
        System.Console.WriteLine("What decrypts to something with ED-E3-6B-43 as first 4 bytes?");
        // We need: Encrypt(X) has first 4 bytes = ED E3 6B 43
        // That means: X = Decrypt(ED E3 6B 43 ?? ?? ?? ??)
        // Let's try Decrypt with the actual bytes from the packet
        var bytes8_15 = HB("EDE36B43F9ED2600");
        var dec815 = pc.Decrypt(bytes8_15);
        System.Console.WriteLine($"Decrypt(EDE36B43 F9ED2600): {H(dec815)}");

        // Hmm wait - what if the whole block [8-15] is NOT encrypted?
        // And it's a COMPUTED checksum?
        // bytes[8-11] = some_hash(packet_data)
        // bytes[12-14] = Encrypt(zeros)[0:3] = Blowfish key verification
        // byte[15] = nonce

        // Let me check: EDE36B43 in big-endian = 0xEDE36B43
        // In little-endian = 0x436BE3ED
        uint val_be = 0xEDE36B43;
        uint val_le = 0x436BE3ED;
        System.Console.WriteLine($"ED-E3-6B-43 as uint32 BE: {val_be} (0x{val_be:X8})");
        System.Console.WriteLine($"ED-E3-6B-43 as uint32 LE: {val_le} (0x{val_le:X8})");

        // Could this be CRC32 of the ENet payload (all zeros for unfilled checksum)?
        // CRC32 of 511 zero bytes (519 - 8 checksum) = ?
        // Actually, CRC32 of some specific data

        // Wait - maybe bytes[8-11] is the outgoingSessionID from ENet CONNECT
        // In LENet, the CONNECT command has a SessionID field at the END of the body
        System.Console.WriteLine();
        System.Console.WriteLine("=== CONNECT.SessionID field ===");
        System.Console.WriteLine("In LENet Protocol.Connect.SessionID, for MaxPeerID<=127:");
        System.Console.WriteLine("  It reads a byte then skips 3. So SessionID is 1 byte.");
        System.Console.WriteLine("  But the HOST generates _nextSessionID starting at 1.");
        System.Console.WriteLine();

        // Let me try a completely different approach:
        // What if the packet is NOT encrypted at all, and the LoL 16.6 client
        // uses a completely different protocol (not standard ENet)?
        //
        // The constant bytes [8-14] = ED-E3-6B-43-F9-ED-26 look like a key fingerprint
        // composed of: [4B = ???][3B = Encrypt(zeros)[0:3]]
        //
        // For the real game: D5-B2-6E-6D-80-92-AD = [4B = ???][3B = Encrypt(zeros)[0:3]]
        //
        // What are the 4 mystery bytes? Let me check if they're related to the
        // Blowfish key itself.
        var keyBytes = Convert.FromBase64String(privateKey);
        System.Console.WriteLine($"Private key raw bytes: {H(keyBytes)}");
        System.Console.WriteLine($"  Key[0:4] = {H(keyBytes, 4, 0)}");

        // CRC32 of key?
        uint crc = Crc32(keyBytes);
        System.Console.WriteLine($"CRC32(key): 0x{crc:X8}");
        System.Console.WriteLine($"Bytes 8-11: 0xEDE36B43");
        System.Console.WriteLine($"Match? {(crc == 0xEDE36B43 ? "YES" : "NO")}");

        // CRC32 of Encrypt(zeros)?
        crc = Crc32(encZeros);
        System.Console.WriteLine($"CRC32(Encrypt(zeros)): 0x{crc:X8}");

        // XOR of key bytes folded to 4 bytes?
        uint xorFold = 0;
        for (int i = 0; i < keyBytes.Length; i += 4)
        {
            uint v = 0;
            for (int j = 0; j < 4 && i + j < keyBytes.Length; j++)
                v |= (uint)keyBytes[i + j] << (j * 8);
            xorFold ^= v;
        }
        System.Console.WriteLine($"XOR-fold key (LE): 0x{xorFold:X8}");

        // Encrypt zeros with just the first 4 bytes of key?
        // That doesn't make sense for Blowfish

        // What if bytes[8-11] = Decrypt(zeros)[4:8]?
        System.Console.WriteLine($"Decrypt(zeros)[4:8] = {H(decZeros, 4, 4)}");
        System.Console.WriteLine($"Bytes 8-11 = ED-E3-6B-43");

        // Or Encrypt(zeros)[4:8]?
        System.Console.WriteLine($"Encrypt(zeros)[4:8] = {H(encZeros, 4, 4)}");

        // Let me check the REAL key too
        var realKeyBytes = Convert.FromBase64String(realKey);
        var realCrc = Crc32(realKeyBytes);
        System.Console.WriteLine();
        System.Console.WriteLine($"Real key raw bytes: {H(realKeyBytes)}");
        System.Console.WriteLine($"CRC32(real key): 0x{realCrc:X8}");
        System.Console.WriteLine($"Real bytes 8-11: 0xD5B26E6D");
        System.Console.WriteLine($"Match? {(realCrc == 0xD5B26E6D ? "YES" : "NO")}");

        // What about CRC32 of the key in different representations?
        // CRC32 of base64 string?
        var keyStr = System.Text.Encoding.ASCII.GetBytes(privateKey);
        System.Console.WriteLine($"CRC32(private key base64 string): 0x{Crc32(keyStr):X8}");
        keyStr = System.Text.Encoding.ASCII.GetBytes(realKey);
        System.Console.WriteLine($"CRC32(real key base64 string): 0x{Crc32(keyStr):X8}");

        // NEW APPROACH: Maybe the ENTIRE packet is Blowfish ECB encrypted,
        // BUT the LoL client sends DIFFERENT data each time (not same CONNECT)
        // because TimeSent varies. And ED-E3-6B-43 at bytes 8-11 is the
        // ECB-encrypted ENet header with a specific TimeSent.

        // But we showed bytes 8-14 are CONSTANT across ALL packets (even retries).
        // TimeSent WOULD vary across retries, so this can't be the ECB-encrypted header.

        // UNLESS TimeSent is NOT in the ENet header at all (maybe hasSentTime=false)
        // For CONNECT without sentTime flag:
        //   [8] SessionID = 0x00  (first CONNECT, no session)
        //   [9] PeerID    = 0x7F (no sentTime flag, so just 0x7F)
        //   [10] CmdByte  = 0x82 (CONNECT | ACK_FLAG)
        //   [11] ChannelID= 0xFF
        //   [12-13] SeqNo = 0x00 0x01
        //   [14-15] = start of CONNECT body
        //
        // So plaintext block [8-15] = 00 7F 82 FF 00 01 7F 00
        //   (where [14]=outPeerID=0x7F, [15]=pad=0x00)

        System.Console.WriteLine();
        System.Console.WriteLine("=== Test: ECB encrypt known ENet CONNECT header ===");

        // If hasSentTime = false, no TimeSent field:
        //   Header: [sessionID=0][peerID=0x7F]
        //   Command: [0x82=CONNECT|ACK][ch=0xFF][seq=0x0001]
        //   Connect body: [outPeer=0x7F][pad=0x00][MTU=0x03E4]...
        var noST = new byte[] { 0x00, 0x7F, 0x82, 0xFF, 0x00, 0x01, 0x7F, 0x00 };
        var encNoST = pc.Encrypt(noST);
        System.Console.WriteLine($"Encrypt(00 7F 82 FF 00 01 7F 00): {H(encNoST)}");
        System.Console.WriteLine($"Expected bytes 8-15:               ED-E3-6B-43-F9-ED-26-??");
        System.Console.WriteLine($"Match first 7? {Same(encNoST, HB("EDE36B43F9ED26"), 7)}");

        // If hasSentTime = true, but sentTime=0:
        //   [sessionID=0][peerID=0xFF][sentTime=0x0000][cmd=0x82][ch=0xFF][seq=0x0001][outPeer=0x7F]
        // Wait, that's 8 bytes: 00 FF 00 00 82 FF 00 01
        var withST0 = new byte[] { 0x00, 0xFF, 0x00, 0x00, 0x82, 0xFF, 0x00, 0x01 };
        var encST0 = pc.Encrypt(withST0);
        System.Console.WriteLine($"Encrypt(00 FF 00 00 82 FF 00 01): {H(encST0)}");

        // Without ACK flag: cmd=0x02 instead of 0x82
        var noACK = new byte[] { 0x00, 0x7F, 0x02, 0xFF, 0x00, 0x01, 0x7F, 0x00 };
        var encNoACK = pc.Encrypt(noACK);
        System.Console.WriteLine($"Encrypt(00 7F 02 FF 00 01 7F 00): {H(encNoACK)}");

        // Try with SENT_TIME flag (0x80) on command byte: 0x82 = CONNECT | nothing
        // In ENet: ProtocolFlag.ACKNOWLEDGE = 0x80, so cmd=0x82 = ACK|CONNECT
        // But maybe real client uses different flags
        var withFlag = new byte[] { 0x00, 0x7F, 0xC2, 0xFF, 0x00, 0x01, 0x7F, 0x00 };
        var encFlag = pc.Encrypt(withFlag);
        System.Console.WriteLine($"Encrypt(00 7F C2 FF 00 01 7F 00): {H(encFlag)}");

        // What plaintext produces ED-E3-6B-43-F9-ED-26-XX?
        // For each XX from 00 to FF, Decrypt() and check if it looks like ENet
        System.Console.WriteLine();
        System.Console.WriteLine("=== Brute-force: what plaintext → ED-E3-6B-43-F9-ED-26-XX? ===");
        for (int xx = 0; xx < 256; xx++)
        {
            var target = new byte[] { 0xED, 0xE3, 0x6B, 0x43, 0xF9, 0xED, 0x26, (byte)xx };
            var plain = pc.Decrypt(target);

            // Check if plaintext looks like ENet header
            byte s = plain[0];
            byte p = plain[1];
            int pid = p & 0x7F;
            bool st = (p & 0x80) != 0;
            byte cmd = plain[st ? 4 : 2];
            int cmdType = cmd & 0x0F;

            bool looksValid = (s == 0x00) && (pid == 0x7F) && (cmdType == 2); // CONNECT
            if (looksValid)
            {
                System.Console.WriteLine($"  XX=0x{xx:X2}: plain={H(plain)} sess={s:X2} peer={pid:X2} st={st} cmd={cmd:X2}(type={cmdType})");
            }
        }

        // Also check if the plaintext matches any valid command for ALL xx values
        System.Console.WriteLine();
        System.Console.WriteLine("=== Valid ENet headers that encrypt to ED-E3-6B-43-F9-ED-26-XX ===");
        for (int xx = 0; xx < 256; xx++)
        {
            var target = new byte[] { 0xED, 0xE3, 0x6B, 0x43, 0xF9, 0xED, 0x26, (byte)xx };
            var plain = pc.Decrypt(target);

            // Season 8 without sentTime: [sess][peer][cmd][ch][seq:2][connect_body:2]
            byte s = plain[0];
            byte p = plain[1];
            int pid = p & 0x7F;
            bool st = (p & 0x80) != 0;

            // Check both with and without sentTime
            for (int hasSentTime = 0; hasSentTime <= 1; hasSentTime++)
            {
                int cmdOff = (hasSentTime == 1) ? 4 : 2;
                if (cmdOff >= 8) continue;
                byte cmd = plain[cmdOff];
                int cmdType = cmd & 0x0F;
                byte ch = (cmdOff + 1 < 8) ? plain[cmdOff + 1] : (byte)0;

                if (cmdType >= 1 && cmdType <= 12 && (pid == 0x7F || pid < 32) && s < 8)
                {
                    System.Console.WriteLine($"  XX=0x{xx:X2} st={hasSentTime}: plain={H(plain)} s={s} p=0x{pid:X2} cmd={cmdType} ch=0x{ch:X2}");
                }
            }
        }

        // NEW THEORY: What if the 519B CONNECT is NOT encrypted at all?
        // Channel 0 (Handshake) is NEVER encrypted.
        // CONNECT is a handshake command.
        // So bytes 8+ might be PLAINTEXT but in a format we don't understand.
        //
        // Let me try parsing with a completely custom format.
        // What if LoL 16.6 doesn't use standard ENet header format at all?
        // What if it uses a "Season 12" format with 4-byte SessionID?
        //
        // Seasson12: MaxPeerID=32767, no checksum, MaxHeaderSizeBase=8
        //   [0-3] SessionID (uint32 BE)
        //   [4-5] PeerID | flags (uint16 BE)
        //   [6-7] TimeSent (uint16 BE, if hasSentTime)
        //   [8+]  Commands

        System.Console.WriteLine();
        System.Console.WriteLine("=== Parse as plaintext with various formats ===");

        // Read actual first packet
        var pktPath = @"D:\LeagueOfLegendsV2\client-private\Game\nethook_logs\SEND_0001_519B.bin";
        byte[] pkt;
        try { pkt = System.IO.File.ReadAllBytes(pktPath); }
        catch { System.Console.WriteLine("Cannot read packet file"); pkt = HB("0000000000000000EDE36B43F9ED267FAAB1E0251537A80A27A9CD3D23E0BC09"); }

        System.Console.WriteLine($"Packet size: {pkt.Length}B");
        System.Console.WriteLine($"First 32: {H(pkt, 32)}");

        // Format A: Seasson12 (no checksum, 8B header)
        System.Console.WriteLine();
        System.Console.WriteLine("Format A: Seasson12 (no checksum, 4B sessID, 2B peerID):");
        uint sessA = (uint)(pkt[0] << 24 | pkt[1] << 16 | pkt[2] << 8 | pkt[3]);
        ushort pidA = (ushort)(pkt[4] << 8 | pkt[5]);
        bool stA = (pidA & 0x8000) != 0;
        pidA = (ushort)(pidA & 0x7FFF);
        System.Console.WriteLine($"  SessionID=0x{sessA:X8} PeerID=0x{pidA:X4} hasST={stA}");
        int cmdOffA = stA ? 8 : 6;
        System.Console.WriteLine($"  @{cmdOffA} Cmd=0x{pkt[cmdOffA]:X2}(type={pkt[cmdOffA] & 0xF}) Ch=0x{pkt[cmdOffA + 1]:X2}");

        // Format B: Season 8 (8B checksum, 1B sess, 1B peer)
        System.Console.WriteLine();
        System.Console.WriteLine("Format B: Seasson8 (8B checksum, 1B sessID, 1B peerID):");
        System.Console.WriteLine($"  Checksum: {H(pkt, 8, 0)}");
        byte sessB = pkt[8];
        byte pidB_raw = pkt[9];
        int pidB = pidB_raw & 0x7F;
        bool stB = (pidB_raw & 0x80) != 0;
        System.Console.WriteLine($"  SessionID=0x{sessB:X2} PeerID=0x{pidB:X2} hasST={stB}");
        int cmdOffB = stB ? 12 : 10;
        if (cmdOffB + 1 < pkt.Length)
            System.Console.WriteLine($"  @{cmdOffB} Cmd=0x{pkt[cmdOffB]:X2}(type={pkt[cmdOffB] & 0xF}) Ch=0x{pkt[cmdOffB + 1]:X2}");

        // Format C: 8B checksum + Season 12 header (4B sess + 2B peer)
        System.Console.WriteLine();
        System.Console.WriteLine("Format C: 8B checksum + Season12-style header:");
        System.Console.WriteLine($"  Checksum: {H(pkt, 8, 0)}");
        uint sessC = (uint)(pkt[8] << 24 | pkt[9] << 16 | pkt[10] << 8 | pkt[11]);
        ushort pidC = (ushort)(pkt[12] << 8 | pkt[13]);
        bool stC = (pidC & 0x8000) != 0;
        pidC = (ushort)(pidC & 0x7FFF);
        System.Console.WriteLine($"  SessionID=0x{sessC:X8} PeerID=0x{pidC:X4} hasST={stC}");
        int cmdOffC = stC ? 16 : 14;
        if (cmdOffC + 1 < pkt.Length)
            System.Console.WriteLine($"  @{cmdOffC} Cmd=0x{pkt[cmdOffC]:X2}(type={pkt[cmdOffC] & 0xF}) Ch=0x{pkt[cmdOffC + 1]:X2}");

        // Format D: COMPLETELY custom - what if [0-7]=zeros, [8-15]=Blowfish tag, [16+]=plaintext ENet?
        System.Console.WriteLine();
        System.Console.WriteLine("Format D: [0-7]=pad [8-15]=tag [16+]=plaintext ENet (Season8):");
        if (pkt.Length > 20)
        {
            byte sessD = pkt[16];
            byte pidD_raw = pkt[17];
            int pidD = pidD_raw & 0x7F;
            bool stD = (pidD_raw & 0x80) != 0;
            System.Console.WriteLine($"  SessionID=0x{sessD:X2} PeerID=0x{pidD:X2} hasST={stD}");
            int cmdOffD = stD ? 20 : 18;
            if (cmdOffD + 1 < pkt.Length)
                System.Console.WriteLine($"  @{cmdOffD} Cmd=0x{pkt[cmdOffD]:X2}(type={pkt[cmdOffD] & 0xF}) Ch=0x{pkt[cmdOffD + 1]:X2}");
        }

        // Format E: Entirely encrypted with ECB, but check if PKTNO 1 uses DEADBEEF session
        // SEND_0001 has 37AA0014 EFBEADDE at [0-7] = session stuff
        System.Console.WriteLine();
        System.Console.WriteLine("Format E: SEND_0001 has checksum=37AA0014 EFBEADDE");
        System.Console.WriteLine("  37AA0014 could be: ConnectToken or Protocol Magic");
        System.Console.WriteLine("  EFBEADDE = 0xDEADBEEF (LE) = our server session ID!");

        // So the packet format might be:
        // [0-3] = ConnectID/Token (37AA0014 = fixed for this connection)
        // [4-7] = SessionID from server (DEADBEEF) or zeros before VERIFY
        // [8-14] = Blowfish key fingerprint (constant per key)
        //          [8-11] = ??? [12-14] = Encrypt(zeros)[0:3]
        // [15] = nonce/sequence
        // [16-516] = encrypted payload
        // [517-518] = footer (Encrypt(zeros)[1:0] reversed)

        // The key fingerprint is [ED-E3-6B-43-F9-ED-26] for private key
        // And [D5-B2-6E-6D-80-92-AD] for real key.
        // The last 3 bytes = Encrypt(zeros)[0:3]. What about the first 4?

        // Let me check: EDE36B43 = Decrypt(zeros)[reversed]?
        // Decrypt(zeros) = 82-BC-62-33-73-11-01-C4
        // Reversed 4: 33-62-BC-82. No.

        // XOR of Encrypt(zeros) and Decrypt(zeros)?
        var xorED = XOR(encZeros, decZeros);
        System.Console.WriteLine($"\nEncrypt(zeros) XOR Decrypt(zeros) = {H(xorED)}");

        // Encrypt(zeros) XOR its own reversed?
        var revEncZ = new byte[8];
        for (int i = 0; i < 8; i++) revEncZ[i] = encZeros[7 - i];
        var xorRev = XOR(encZeros, revEncZ);
        System.Console.WriteLine($"Encrypt(zeros) XOR reversed = {H(xorRev)}");

        // What about: Encrypt(1) or Encrypt(some small integer)?
        for (int val = 0; val < 8; val++)
        {
            var block = new byte[8];
            block[7] = (byte)val;  // LE
            var enc = pc.Encrypt(block);
            System.Console.WriteLine($"Encrypt({val} LE): {H(enc)}");
        }
        System.Console.WriteLine();
        for (int val = 0; val < 8; val++)
        {
            var block = new byte[8];
            block[0] = (byte)val;  // BE
            var enc = pc.Encrypt(block);
            System.Console.WriteLine($"Encrypt({val} BE): {H(enc)}");
        }

        // Brute force: find what 8-byte block encrypts to start with ED-E3-6B-43-F9-ED-26
        System.Console.WriteLine();
        System.Console.WriteLine("=== Brute: what encrypts to EDE36B43 F9ED26?? ===");
        // We know Encrypt(X) starts with ED-E3-6B-43-F9-ED-26
        // Decrypt(ED-E3-6B-43-F9-ED-26-XX) = X for each XX
        // Let's check if any of these look like a meaningful pattern
        var meaningfulPlains = new System.Collections.Generic.List<string>();
        for (int xx = 0; xx < 256; xx++)
        {
            var ct = new byte[] { 0xED, 0xE3, 0x6B, 0x43, 0xF9, 0xED, 0x26, (byte)xx };
            var pt = pc.Decrypt(ct);

            // Check if plaintext has structure:
            // - First few bytes zero (header padding)
            // - Or all zeros (would be Encrypt(zeros) but we know that's F9ED26...)
            // - Or looks like [sess=0][peer=0x7F][some pattern]
            // - Or is a small integer
            bool interesting = false;
            // Low byte count (mostly zeros)
            int zeroCount = 0;
            foreach (byte b in pt) if (b == 0) zeroCount++;
            if (zeroCount >= 5) interesting = true;

            // Matches known ENet header patterns
            if (pt[0] == 0 && (pt[1] == 0x7F || pt[1] == 0xFF)) interesting = true;

            // Small values
            uint val = (uint)(pt[0] << 24 | pt[1] << 16 | pt[2] << 8 | pt[3]);
            if (val <= 255) interesting = true;

            if (interesting)
                meaningfulPlains.Add($"  XX=0x{xx:X2}: {H(pt)} (zeros={zeroCount}, uint32BE=0x{val:X8})");
        }
        foreach (var s in meaningfulPlains) System.Console.WriteLine(s);

        // Now try with real key
        System.Console.WriteLine();
        System.Console.WriteLine("=== Brute for REAL key: what encrypts to D5B26E6D 8092AD?? ===");
        for (int xx = 0; xx < 256; xx++)
        {
            var ct = new byte[] { 0xD5, 0xB2, 0x6E, 0x6D, 0x80, 0x92, 0xAD, (byte)xx };
            var pt = rc.Decrypt(ct);

            int zeroCount = 0;
            foreach (byte b in pt) if (b == 0) zeroCount++;
            uint val = (uint)(pt[0] << 24 | pt[1] << 16 | pt[2] << 8 | pt[3]);
            bool interesting = zeroCount >= 5 || (pt[0] == 0 && (pt[1] == 0x7F || pt[1] == 0xFF)) || val <= 255;

            if (interesting)
                System.Console.WriteLine($"  XX=0x{xx:X2}: {H(pt)} (zeros={zeroCount}, uint32BE=0x{val:X8})");
        }

        System.Console.WriteLine();
        System.Console.WriteLine("=== FINAL: Complete packet structure hypothesis ===");
    }

    static string H(byte[] d, int len = -1, int off = 0)
    {
        if (len < 0) len = d.Length;
        len = Math.Min(len, d.Length - off);
        if (len <= 0) return "(empty)";
        return BitConverter.ToString(d, off, len);
    }

    static byte[] HB(string hex)
    {
        hex = hex.Replace("-", "").Replace(" ", "");
        var b = new byte[hex.Length / 2];
        for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return b;
    }

    static byte[] XOR(byte[] a, byte[] b)
    {
        var r = new byte[Math.Min(a.Length, b.Length)];
        for (int i = 0; i < r.Length; i++) r[i] = (byte)(a[i] ^ b[i]);
        return r;
    }

    static uint Crc32(byte[] data)
    {
        uint crc = 0xFFFFFFFF;
        foreach (byte b in data)
        {
            crc ^= b;
            for (int i = 0; i < 8; i++)
                crc = (crc >> 1) ^ (crc & 1) * 0xEDB88320;
        }
        return ~crc;
    }

    static bool Same(byte[] a, byte[] b, int len)
    {
        for (int i = 0; i < len && i < a.Length && i < b.Length; i++)
            if (a[i] != b[i]) return false;
        return true;
    }
}
