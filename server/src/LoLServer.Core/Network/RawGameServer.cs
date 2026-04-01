using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using LoLServer.Core.Config;
using LoLServer.Core.Protocol;
using LoLServer.Core.Protocol.Packets;

namespace LoLServer.Core.Network;

/// <summary>
/// Raw UDP game server for modern LoL client (16.6+).
///
/// PROTOCOL (confirmed by Ghidra decompilation, April 2026):
///
/// Server → Client packet format:
///   Plaintext: [2B peerID LE][4B CRC_NONCE BE][1B flags][ENet commands...]
///   Encrypted with Double CFB (Blowfish, IV=0): encrypt → reverse → encrypt
///   Sent raw (no session ID prefix, no CRC prefix, no LNPBlob).
///
/// CRC_NONCE = htonl(~CRC32) computed over a virtual struct:
///   Init = (peerID_lo | 0xFFFFFF00) ^ 0xB1F740B4
///   Process order: peerID bytes, local_res10 (=1 as uint64 LE), 8 timestamp bytes, payload
///
/// Client → Server: 519-byte packets with LNPBlob header:
///   [4B magic 0x37AA0014][4B SessionID LE][payload...][2B footer]
/// </summary>
public class RawGameServer : IGameServer, IDisposable
{
    private UdpClient? _socket;
    private readonly int _port;
    private readonly GameConfig _config;
    private readonly PacketHandler _handler;
    private readonly Dictionary<ushort, ClientInfo> _clients = new();
    private readonly ConcurrentDictionary<string, PeerInfo> _peers = new();
    private readonly BlowFish _cipher;
    private readonly byte[] _blowfishKey;
    private bool _running;
    private ushort _nextPeerId;
    private uint _sessionId = 0xDEADBEEF;

    // LNPBlob magic constant
    private const uint LNPBLOB_MAGIC = 0x37AA0014;

    public event Action<string>? OnLog;
    public IReadOnlyDictionary<ushort, ClientInfo> Clients => _clients;

    public RawGameServer(int port, GameConfig config)
    {
        _port = port;
        _config = config;
        _handler = new PacketHandler(config, this);
        _blowfishKey = Convert.FromBase64String(config.BlowfishKey);
        _cipher = new BlowFish(_blowfishKey);
    }

    public void Start()
    {
        Log("=== LoL Private Server (Double CFB Mode) ===");
        Log($"Port: {_port}");
        Log($"Blowfish Key: {_config.BlowfishKey} ({_blowfishKey.Length} bytes)");
        Log($"BF_encrypt(zeros) = {BitConverter.ToString(_cipher.EncryptBlock(new byte[8]))}");
        Log($"SessionID: 0x{_sessionId:X8}");
        Log($"Players: {_config.Players.Count}");

        _socket = new UdpClient(_port);
        _running = true;

        Log($"[OK] Listening on UDP port {_port}");
        Log("Waiting for LoL client connection...");

        RunReceiveLoop();
    }

    private void RunReceiveLoop()
    {
        while (_running)
        {
            IPEndPoint? remote = null;
            byte[] data;
            try
            {
                data = _socket!.Receive(ref remote);
            }
            catch (SocketException) when (!_running) { break; }
            catch (SocketException ex) { Log($"[ERROR] {ex.Message}"); continue; }

            ProcessPacket(data, remote!);
        }
    }

    private void ProcessPacket(byte[] data, IPEndPoint remote)
    {
        var remoteKey = remote.ToString();
        var peer = _peers.GetOrAdd(remoteKey, _ =>
        {
            var p = new PeerInfo
            {
                Remote = remote,
                PeerId = _nextPeerId++,
            };
            Log($"[NEW PEER] {remoteKey} → PeerId={p.PeerId}");
            return p;
        });
        peer.PacketCount++;

        bool verbose = peer.PacketCount <= 20;

        if (data.Length < 8)
        {
            if (verbose) Log($"[{remoteKey}] #{peer.PacketCount} too short ({data.Length}B)");
            return;
        }

        // Check for LNPBlob header (client→server 519B format)
        uint magic = ReadBE32(data, 0);
        if (magic == LNPBLOB_MAGIC && data.Length >= 16)
        {
            HandleClientPacket(data, peer, verbose);
            return;
        }

        // Otherwise try to decrypt as CFB (for any non-LNPBlob packets)
        byte[] decrypted = CfbDecrypt(data);

        if (verbose)
        {
            Log($"[{remoteKey}] #{peer.PacketCount} {data.Length}B (non-LNPBlob)");
            Log($"  Dec: {Hex(decrypted, 32)}");
        }
    }

    /// <summary>
    /// Handle the client's 519-byte packets with LNPBlob header.
    /// Format: [4B magic][4B sessID_LE][payload...][2B footer]
    /// </summary>
    private void HandleClientPacket(byte[] data, PeerInfo peer, bool verbose)
    {
        // Extract session ID from LNPBlob (little-endian in bytes 4-7)
        uint sessIdLE = (uint)(data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24));

        // Extract connection token from bytes 8-11 (constant per connection)
        if (data.Length >= 12)
        {
            uint connToken = ReadBE32(data, 8);
            if (peer.ConnectToken == 0)
            {
                peer.ConnectToken = connToken;
                Log($"  [TOKEN] Connection token: 0x{connToken:X8}");
            }
        }

        if (verbose)
        {
            Log($"[CLIENT] #{peer.PacketCount} {data.Length}B LNPBlob sessID=0x{sessIdLE:X8} token=0x{peer.ConnectToken:X8}");
            Log($"  Header: {Hex(data, 20)}");
            // Log full content of non-519B packets (these are important!)
            if (data.Length != 519)
                Log($"  FULL: {Hex(data, data.Length)}");
        }

        if (!peer.Connected)
        {
            peer.Connected = true;
            peer.OutgoingPeerID = 1;
            Log($"  [HANDSHAKE] ECHO-ONLY mode");
            EnsureClientInfo(peer);
        }

        // MINIMAL PLAINTEXT: 7 bytes after token = 0 CFB blocks = NO encryption!
        // Format: [4B token][2B peerID=0][4B nonce][1B flags=0x03] = 11 bytes total
        {
            uint nonce = 0xB5053BE0; // CRC with local_res10=1, peerID=0, no payload
            var minimal = new byte[11];
            WriteBE32(minimal, 0, peer.ConnectToken); // token (4B, skipped by client)
            WriteLE16(minimal, 4, 0); // peerID = 0
            WriteBE32(minimal, 6, nonce); // CRC nonce
            minimal[10] = 0x03; // flags = VERIFY_CONNECT
            Log($"  [MINIMAL-VC] 11B plaintext, nonce=0x{nonce:X8}");
            Send(minimal, peer);

            // Also try with nonce in LE
            var minimalLE = (byte[])minimal.Clone();
            WriteLE32(minimalLE, 6, nonce);
            Log($"  [MINIMAL-VC-LE] 11B nonce_LE");
            Send(minimalLE, peer);

            // Try with local_res10 = 0 (nonce = 0xB2F3D8E6)
            uint nonce0 = 0xB2F3D8E6;
            var min0 = (byte[])minimal.Clone();
            WriteBE32(min0, 6, nonce0);
            Log($"  [MINIMAL-VC-LR0] 11B nonce=0x{nonce0:X8} (local_res10=0)");
            Send(min0, peer);
        }

        // CORRECT FORMAT: Double CFB with computed CRC nonce
        // Format: [2B peerID LE][4B CRC_nonce BE][1B flags][36B VERIFY_CONNECT body BE]
        // Then prepend 4B token, double CFB encrypt, send
        {
            byte[] verifyBody = {
                0x00, 0x01,  // outPeerID = 1
                0x03, 0xE4,  // MTU = 996
                0x00, 0x00, 0x80, 0x00,  // windowSize = 32768
                0x00, 0x00, 0x00, 0x20,  // channelCount = 32
                0x00, 0x00, 0x00, 0x00,  // inBW
                0x00, 0x00, 0x00, 0x00,  // outBW
                0x00, 0x00, 0x00, 0x20,  // throttleInt
                0x00, 0x00, 0x00, 0x02,  // throttleAcc
                0x00, 0x00, 0x00, 0x02,  // throttleDec
            };

            // Compute CRC nonce: peerID=0, local_res10=1, no timestamp, payload=verifyBody
            byte peerLo = 0, peerHi = 0;
            uint crc = ((uint)peerLo | 0xFFFFFF00u) ^ 0xB1F740B4u;
            crc = CrcByte(crc, peerHi);
            byte[] lr = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            foreach (var b in lr) crc = CrcByte(crc, b);
            for (int i = 0; i < 8; i++) crc = CrcByte(crc, 0); // timestamp
            foreach (var b in verifyBody) crc = CrcByte(crc, b);
            uint nonce = ~crc;

            // Build plaintext
            var pt = new byte[2 + 4 + 1 + verifyBody.Length]; // 39 bytes
            WriteLE16(pt, 0, 0); // peerID = 0
            WriteBE32(pt, 2, nonce); // CRC nonce
            pt[6] = 0x03; // flags = VERIFY_CONNECT (cmd type 3)
            Array.Copy(verifyBody, 0, pt, 7, verifyBody.Length);

            // Double CFB encrypt
            var enc = DoubleCfbEncrypt(pt);

            // Send with 4B token prefix (skipped by client)
            var pkt = new byte[4 + enc.Length];
            WriteBE32(pkt, 0, peer.ConnectToken);
            Array.Copy(enc, 0, pkt, 4, enc.Length);
            Log($"  [CORRECT-VC] nonce=0x{nonce:X8} peerID=0 flags=0x03 ({pkt.Length}B)");
            Send(pkt, peer);

            // Also without token prefix
            Log($"  [CORRECT-VC-NP] no prefix ({enc.Length}B)");
            Send(enc, peer);
        }

        // Echo for handshake progression
        if (data.Length > 8)
        {
            var echo = new byte[data.Length - 8];
            Array.Copy(data, 8, echo, 0, echo.Length);
            Send(echo, peer);
        }

        // Other test variants (kept for comparison)
        // Hypothesis: crypto might be disabled for recv (*param_3 == '\0')
        // Format: [4B padding (skipped by client)][plaintext ENet data]
        {
            ushort sentTime = (ushort)(Environment.TickCount & 0xFFFF);
            var pt = new byte[4 + 48]; // 4 pad + 48 ENet
            // Padding: use token, zeros, or session ID
            WriteBE32(pt, 0, peer.ConnectToken); // or _sessionId or 0
            int o = 4;
            WriteBE32(pt, o, _sessionId); o += 4;
            WriteBE16(pt, o, (ushort)(peer.OutgoingPeerID | 0x8000)); o += 2;
            WriteBE16(pt, o, sentTime); o += 2;
            pt[o] = 0x83; o++; // VERIFY_CONNECT | SENT_TIME
            pt[o] = 0xFF; o++; // channel
            WriteBE16(pt, o, peer.VerifySeqNo); o += 2;
            WriteBE16(pt, o, peer.OutgoingPeerID); o += 2;
            WriteBE16(pt, o, 996); o += 2;
            WriteBE32(pt, o, 32768); o += 4;
            WriteBE32(pt, o, 32); o += 4;
            o += 20; // zeros
            Log($"  [PLAINTEXT-ONLY] {pt.Length}B");
            Send(pt, peer);

            // Also try with zero padding
            var pt0 = (byte[])pt.Clone();
            WriteBE32(pt0, 0, 0);
            Log($"  [PLAINTEXT-ZERO] {pt0.Length}B");
            Send(pt0, peer);

            // Also try single CFB encrypted (no echo for clean test)
            var enet = new byte[48];
            Array.Copy(pt, 4, enet, 0, 48);
            var enc = CfbEncrypt(enet);
            var encWithPad = new byte[4 + enc.Length];
            WriteBE32(encWithPad, 0, peer.ConnectToken);
            Array.Copy(enc, 0, encWithPad, 4, enc.Length);
            Log($"  [SCFB-ONLY] {encWithPad.Length}B (no echo!)");
            Send(encWithPad, peer);

            // V-2LAYER: Two-layer encryption
            // Inner: double CFB of [peerID(2)][nonce(4)][flags(1)][payload(36)] = 43B
            // Outer: single CFB of [4B header][inner_encrypted(43B)] = 47B
            {
                // Build inner plaintext (CRC format)
                // For now, use nonce=0 (will fail CRC but tests the path)
                var inner = new byte[43];
                WriteLE16(inner, 0, peer.OutgoingPeerID); // peerID LE
                WriteBE32(inner, 2, 0); // nonce placeholder
                inner[6] = 0x03; // flags = VERIFY_CONNECT
                int z = 7;
                WriteBE16(inner, z, peer.OutgoingPeerID); z += 2;
                WriteBE16(inner, z, 996); z += 2;
                WriteBE32(inner, z, 32768); z += 4;
                WriteBE32(inner, z, 32); z += 4;
                z += 20; // zeros

                var innerEnc = DoubleCfbEncrypt(inner);

                // Outer: single CFB of [sessID][innerEnc]
                var outer = new byte[4 + innerEnc.Length];
                WriteBE32(outer, 0, _sessionId);
                Array.Copy(innerEnc, 0, outer, 4, innerEnc.Length);
                var outerEnc = CfbEncrypt(outer);
                Log($"  [2LAYER] Outer-sCFB(sessID+Inner-dCFB) ({outerEnc.Length}B)");
                Send(outerEnc, peer);

                // Also try without inner encryption (just outer single CFB)
                var outerPlain = new byte[4 + inner.Length];
                WriteBE32(outerPlain, 0, _sessionId);
                Array.Copy(inner, 0, outerPlain, 4, inner.Length);
                var outerOnlyEnc = CfbEncrypt(outerPlain);
                Log($"  [1LAYER] Outer-sCFB(sessID+plainInner) ({outerOnlyEnc.Length}B)");
                Send(outerOnlyEnc, peer);
            }

            peer.VerifySeqNo++;
        }

        if (!peer.GameInitSent && peer.PacketCount > 15)
        {
            ScheduleGameInit(peer);
        }
    }

    /// <summary>
    /// Send a VERIFY_CONNECT packet using the confirmed Ghidra format.
    ///
    /// Plaintext: [2B peerID LE][4B CRC_NONCE BE][1B flags][36B ENet VERIFY_CONNECT body BE]
    /// Encrypted: Double CFB (encrypt → reverse → encrypt), Blowfish IV=0
    /// Sent: raw encrypted bytes, no prefix
    /// </summary>
    private void SendVerifyConnect(PeerInfo peer)
    {
        ushort peerID = peer.OutgoingPeerID;
        byte commandType = 0x03; // VERIFY_CONNECT
        byte flags = commandType; // no timestamp (bit7=0), command_type in bits 0-6

        // --- Build the ENet VERIFY_CONNECT command body (36 bytes, big-endian) ---
        var body = new byte[36];
        int off = 0;
        WriteBE16(body, off, peerID); off += 2;       // outPeerID
        WriteBE16(body, off, 996); off += 2;           // MTU
        WriteBE32(body, off, 32768); off += 4;         // windowSize
        WriteBE32(body, off, 32); off += 4;            // channelCount
        WriteBE32(body, off, 0); off += 4;             // inBandwidth
        WriteBE32(body, off, 0); off += 4;             // outBandwidth
        WriteBE32(body, off, 32); off += 4;            // throttleInterval
        WriteBE32(body, off, 2); off += 4;             // throttleAccel
        WriteBE32(body, off, 2); off += 4;             // throttleDec

        // --- Compute CRC_NONCE ---
        // Virtual struct layout (as byte array):
        //   [0..7]  = local_res10 = 1 (uint64 LE)
        //   [8..9]  = peerID (LE)
        //
        // CRC processing order: byte[8], byte[9], byte[0..7], 8 timestamp bytes, payload bytes
        // Init: (byte[8] | 0xFFFFFF00) ^ 0xB1F740B4
        byte peerLo = (byte)(peerID & 0xFF);
        byte peerHi = (byte)((peerID >> 8) & 0xFF);

        // CRC init from byte[8] (peerID low byte)
        uint crc = ((uint)peerLo | 0xFFFFFF00u) ^ 0xB1F740B4u;

        // Process byte[9] (peerID high byte)
        crc = CrcByte(crc, peerHi);

        // Process bytes[0..7] = local_res10 = 1 as uint64 LE
        byte[] localRes10 = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        for (int i = 0; i < 8; i++)
            crc = CrcByte(crc, localRes10[i]);

        // Process 8 timestamp bytes (all zeros - no timestamp since bit7 of flags is 0)
        for (int i = 0; i < 8; i++)
            crc = CrcByte(crc, 0x00);

        // Process payload bytes (the VERIFY_CONNECT body)
        for (int i = 0; i < body.Length; i++)
            crc = CrcByte(crc, body[i]);

        // Finalize: htonl(~crc) - store as big-endian in packet
        uint crcNonce = ~crc;

        // --- Build plaintext packet ---
        // [2B peerID LE][4B CRC_NONCE BE][1B flags][36B body] = 43 bytes
        var plaintext = new byte[2 + 4 + 1 + body.Length];
        int p = 0;
        WriteLE16(plaintext, p, peerID); p += 2;
        WriteBE32(plaintext, p, crcNonce); p += 4;
        plaintext[p] = flags; p += 1;
        Array.Copy(body, 0, plaintext, p, body.Length);

        // --- Send ENet VERIFY_CONNECT with SINGLE CFB + token prefix ---
        // Analysis shows client uses SINGLE CFB, NOT double!
        // Standard ENet: [4B sessID][2B peerID|flags][2B sentTime][cmd...][body...]
        {
            var enetPlain = new byte[48];
            int ep = 0;
            WriteBE32(enetPlain, ep, _sessionId); ep += 4;
            WriteBE16(enetPlain, ep, (ushort)(peer.OutgoingPeerID | 0x8000)); ep += 2;
            WriteBE16(enetPlain, ep, (ushort)(Environment.TickCount & 0xFFFF)); ep += 2;
            enetPlain[ep] = 0x83; ep++; // VERIFY_CONNECT | SENT_TIME
            enetPlain[ep] = 0xFF; ep++; // channel
            WriteBE16(enetPlain, ep, peer.VerifySeqNo); ep += 2;
            Array.Copy(body, 0, enetPlain, ep, body.Length);

            var singleEnc = CfbEncrypt(enetPlain);

            // V1: Just single CFB (no prefix)
            Log($"  [VC-S1] Single CFB no prefix ({singleEnc.Length}B)");
            Send(singleEnc, peer);

            // V2: Token prefix + single CFB
            var withToken = new byte[4 + singleEnc.Length];
            WriteBE32(withToken, 0, peer.ConnectToken); // EDE36B43
            Array.Copy(singleEnc, 0, withToken, 4, singleEnc.Length);
            Log($"  [VC-S2] Token + single CFB ({withToken.Length}B)");
            Send(withToken, peer);

            // V3: Token prefix + single CFB (LE token)
            var withTokenLE = new byte[4 + singleEnc.Length];
            WriteLE32(withTokenLE, 0, peer.ConnectToken);
            Array.Copy(singleEnc, 0, withTokenLE, 4, singleEnc.Length);
            Log($"  [VC-S3] Token(LE) + single CFB ({withTokenLE.Length}B)");
            Send(withTokenLE, peer);

            // V4: Double CFB with ENet format (no CRC nonce)
            var dblEnc = DoubleCfbEncrypt(enetPlain);
            Log($"  [VC-D1] Double CFB ENet ({dblEnc.Length}B)");
            Send(dblEnc, peer);

            // V5: Token + double CFB ENet
            var dblWithToken = new byte[4 + dblEnc.Length];
            WriteBE32(dblWithToken, 0, peer.ConnectToken);
            Array.Copy(dblEnc, 0, dblWithToken, 4, dblEnc.Length);
            Log($"  [VC-D2] Token + double CFB ENet ({dblWithToken.Length}B)");
            Send(dblWithToken, peer);
        }

        // Also send double CFB of CRC format WITH token prefix
        var encrypted = DoubleCfbEncrypt(plaintext);

        // V6: Token + double CFB of CRC format (the missing combo!)
        var tokenCrc = new byte[4 + encrypted.Length];
        WriteBE32(tokenCrc, 0, peer.ConnectToken);
        Array.Copy(encrypted, 0, tokenCrc, 4, encrypted.Length);
        Log($"  [VC-D3] Token + dblCFB CRC format ({tokenCrc.Length}B)");
        Send(tokenCrc, peer);

        // V7: Also try with LE token
        WriteLE32(tokenCrc, 0, peer.ConnectToken);
        Log($"  [VC-D4] Token(LE) + dblCFB CRC ({tokenCrc.Length}B)");
        Send(tokenCrc, peer);

        // V8: No prefix, just the CRC-format double CFB
        Log($"  [VC-D5] dblCFB CRC no prefix ({encrypted.Length}B)");
        Send(encrypted, peer);

        // V9-V11: PLAINTEXT with 4B padding (if crypto is disabled for recv!)
        {
            // Rebuild ENet plaintext for this scope
            var pt = new byte[48];
            int z = 0;
            WriteBE32(pt, z, _sessionId); z += 4;
            WriteBE16(pt, z, (ushort)(peer.OutgoingPeerID | 0x8000)); z += 2;
            WriteBE16(pt, z, (ushort)(Environment.TickCount & 0xFFFF)); z += 2;
            pt[z] = 0x83; z++; pt[z] = 0xFF; z++;
            WriteBE16(pt, z, peer.VerifySeqNo); z += 2;
            WriteBE16(pt, z, peer.OutgoingPeerID); z += 2;
            WriteBE16(pt, z, 996); z += 2;
            WriteBE32(pt, z, 32768); z += 4;
            WriteBE32(pt, z, 32); z += 4;
            z += 20; // zeros

            // Token + PLAINTEXT
            var ptPkt = new byte[4 + pt.Length];
            WriteBE32(ptPkt, 0, peer.ConnectToken);
            Array.Copy(pt, 0, ptPkt, 4, pt.Length);
            Log($"  [VC-PT1] Token + PLAINTEXT ({ptPkt.Length}B)");
            Send(ptPkt, peer);

            // Zero pad + PLAINTEXT
            var ptZero = new byte[4 + pt.Length];
            Array.Copy(pt, 0, ptZero, 4, pt.Length);
            Log($"  [VC-PT2] Zeros + PLAINTEXT ({ptZero.Length}B)");
            Send(ptZero, peer);
        }

        peer.VerifySeqNo++;
    }

    private void ScheduleGameInit(PeerInfo peer)
    {
        if (peer.GameInitSent) return;
        peer.GameInitSent = true;

        Log($"  [GAME_INIT] Sending game initialization packets");

        // Send a PING to keep the connection alive
        SendPing(peer);
    }

    private void SendPing(PeerInfo peer)
    {
        // Build PING in the same confirmed format:
        // [2B peerID LE][4B CRC_NONCE BE][1B flags][PING body]
        // PING command_type = 0x05, no body (0 bytes payload)
        ushort peerID = peer.PeerId;
        byte flags = 0x05; // PING, no timestamp

        byte peerLo = (byte)(peerID & 0xFF);
        byte peerHi = (byte)((peerID >> 8) & 0xFF);

        uint crc = ((uint)peerLo | 0xFFFFFF00u) ^ 0xB1F740B4u;
        crc = CrcByte(crc, peerHi);

        byte[] localRes10 = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        for (int i = 0; i < 8; i++)
            crc = CrcByte(crc, localRes10[i]);

        // 8 timestamp bytes (zeros)
        for (int i = 0; i < 8; i++)
            crc = CrcByte(crc, 0x00);

        // No payload for PING
        uint crcNonce = ~crc;

        // [2B peerID LE][4B CRC_NONCE BE][1B flags] = 7 bytes
        var plaintext = new byte[7];
        int p = 0;
        WriteLE16(plaintext, p, peerID); p += 2;
        WriteBE32(plaintext, p, crcNonce); p += 4;
        plaintext[p] = flags;

        var encrypted = DoubleCfbEncrypt(plaintext);
        Send(encrypted, peer);
    }

    // ========================================================================
    //  CRC32 HELPERS
    // ========================================================================

    /// <summary>
    /// Process a single byte through CRC32 using the game's table.
    /// The game uses polynomial 0x04C11DB7 (CRC-32/MPEG-2, MSB-first, non-reflected).
    /// Processing: crc = (crc << 8 | byte) ^ table[crc >> 24]
    /// This matches the Ghidra decompilation of FUN_140577f10.
    /// </summary>
    private static uint CrcByte(uint crc, byte b)
    {
        crc = ((crc << 8) | b) ^ _crcTable[crc >> 24];
        return crc;
    }

    // CRC-32 table with polynomial 0x04C11DB7 (from binary at DAT_141947e80)
    private static readonly uint[] _crcTable = GenerateCrcTable();
    private static uint[] GenerateCrcTable()
    {
        var table = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint crc = i << 24;
            for (int j = 0; j < 8; j++)
                crc = (crc & 0x80000000) != 0 ? (crc << 1) ^ 0x04C11DB7u : crc << 1;
            table[i] = crc;
        }
        return table;
    }

    /// <summary>ENet-compatible CRC32 (standard CRC32 / ISO 3309)</summary>
    private static uint Crc32(byte[] data)
    {
        uint crc = 0xFFFFFFFF;
        foreach (byte b in data)
        {
            crc ^= b;
            for (int i = 0; i < 8; i++)
                crc = (crc >> 1) ^ (0xEDB88320 & ~((crc & 1) - 1));
        }
        return ~crc;
    }

    // ========================================================================
    //  BLOWFISH CFB ENCRYPTION (per-packet fresh IV=0)
    // ========================================================================

    /// <summary>
    /// Encrypt with Blowfish CFB using fresh IV=zeros (per-packet, no persistent state).
    /// </summary>
    private byte[] CfbEncrypt(byte[] plaintext)
    {
        var result = (byte[])plaintext.Clone(); // start with copy (trailing bytes stay as-is!)
        var feedback = new byte[8]; // IV = zeros
        int fullBlocks = plaintext.Length / 8; // ONLY full blocks! (game: param_3 >> 3)

        for (int block = 0; block < fullBlocks; block++)
        {
            int i = block * 8;
            var keystream = _cipher.EncryptBlock(feedback);
            for (int j = 0; j < 8; j++)
                result[i + j] = (byte)(plaintext[i + j] ^ keystream[j]);

            Array.Copy(result, i, feedback, 0, 8);
        }
        // Remaining bytes (plaintext.Length % 8) are NOT encrypted! (matches game behavior)

        return result;
    }

    /// <summary>
    /// Double CFB encrypt: CFB encrypt → reverse → CFB encrypt (both IV=0).
    /// This matches the game's FUN_14058ef90 encryption pattern.
    /// </summary>
    private byte[] DoubleCfbEncrypt(byte[] plaintext)
    {
        // Pass 1: CFB encrypt
        var result = CfbEncrypt(plaintext);
        // Reverse ALL bytes (game reverses uVar14 = full length, not just processed blocks!)
        Array.Reverse(result);
        // Pass 2: CFB encrypt
        result = CfbEncrypt(result);
        return result;
    }

    /// <summary>
    /// Decrypt with Blowfish CFB using fresh IV=zeros (per-packet).
    /// </summary>
    private byte[] CfbDecrypt(byte[] ciphertext)
    {
        var result = (byte[])ciphertext.Clone(); // trailing bytes stay as-is
        var feedback = new byte[8]; // IV = zeros
        int fullBlocks = ciphertext.Length / 8; // ONLY full blocks!

        for (int block = 0; block < fullBlocks; block++)
        {
            int i = block * 8;
            var keystream = _cipher.EncryptBlock(feedback);
            Array.Copy(ciphertext, i, feedback, 0, 8); // feedback = input BEFORE XOR
            for (int j = 0; j < 8; j++)
                result[i + j] = (byte)(ciphertext[i + j] ^ keystream[j]);
        }
        // Remaining bytes NOT decrypted (matches game behavior)

        return result;
    }

    // ========================================================================
    //  HELPERS
    // ========================================================================

    private void Send(byte[] data, PeerInfo peer)
    {
        try
        {
            _socket!.Send(data, data.Length, peer.Remote);
        }
        catch (Exception ex) { Log($"  [ERROR] Send failed: {ex.Message}"); }
    }

    private static ushort ReadBE16(byte[] buf, int off) => (ushort)((buf[off] << 8) | buf[off + 1]);
    private static uint ReadBE32(byte[] buf, int off) => (uint)((buf[off] << 24) | (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3]);
    private static void WriteBE16(byte[] buf, int off, ushort val) { buf[off] = (byte)(val >> 8); buf[off + 1] = (byte)val; }
    private static void WriteBE32(byte[] buf, int off, uint val) { buf[off] = (byte)(val >> 24); buf[off + 1] = (byte)(val >> 16); buf[off + 2] = (byte)(val >> 8); buf[off + 3] = (byte)val; }
    private static void WriteLE16(byte[] buf, int off, ushort val) { buf[off] = (byte)val; buf[off + 1] = (byte)(val >> 8); }
    private static void WriteLE32(byte[] buf, int off, uint val) { buf[off] = (byte)val; buf[off + 1] = (byte)(val >> 8); buf[off + 2] = (byte)(val >> 16); buf[off + 3] = (byte)(val >> 24); }
    private static string Hex(byte[] d, int max = 32) => BitConverter.ToString(d, 0, Math.Min(max, d.Length));

    private ClientInfo EnsureClientInfo(PeerInfo peer)
    {
        if (!_clients.TryGetValue(peer.PeerId, out var client))
        {
            client = new ClientInfo { Peer = null!, ClientId = peer.PeerId, State = ClientState.Connected };
            var pc = peer.PeerId < _config.Players.Count ? _config.Players[peer.PeerId] : _config.Players[0];
            client.Cipher = BlowFish.FromBase64(pc.BlowfishKey ?? _config.BlowfishKey);
            _clients[peer.PeerId] = client;
            Log($"  [CLIENT] Created PeerId={peer.PeerId}");
        }
        return client;
    }

    public void SendPacket(ClientInfo client, byte[] data, Channel channel) { /* TODO */ }
    public void BroadcastPacket(byte[] data, Channel channel) { }
    public void BroadcastPacketToTeam(byte[] data, Channel channel, TeamId team) { }

    private void Log(string msg) { var f = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}"; Console.WriteLine(f); OnLog?.Invoke(f); }
    public void Stop() { _running = false; _socket?.Close(); }
    public void Dispose() { Stop(); _socket?.Dispose(); }

    private class PeerInfo
    {
        public IPEndPoint Remote { get; set; } = null!;
        public ushort PeerId { get; set; }
        public ushort OutgoingPeerID { get; set; }
        public bool Connected { get; set; }
        public int PacketCount { get; set; }
        public bool GameInitSent { get; set; }
        public ushort VerifySeqNo { get; set; } = 1;
        public uint ConnectToken { get; set; }
    }
}
