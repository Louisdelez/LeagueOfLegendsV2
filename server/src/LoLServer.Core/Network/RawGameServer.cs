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
        var bfTest = _cipher.EncryptBlock(new byte[8]);
        Log($"BF_encrypt(zeros) = {BitConverter.ToString(bfTest)}");
        Log($"P[0] = 0x{_cipher.PBox[0]:X8} (client has 0xBBCD2876)");
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
        }

        // Decrypt the payload: bytes after LNPBlob header (12B) are encrypted
        // The encrypted data includes 4B preamble (not encrypted) + encrypted CRC layer
        // But for < 8B payload, it's plaintext (0 CFB blocks)
        if (data.Length > 12)
        {
            int payloadLen = data.Length - 12;
            byte[] payload = new byte[payloadLen];
            Array.Copy(data, 12, payload, 0, payloadLen);

            // Double CFB decrypt
            byte[] decrypted = DoubleCfbDecrypt(payload);

            // Parse: [2B peerID LE][4B CRC nonce][1B flags][body...]
            if (decrypted.Length >= 7)
            {
                ushort peerID = (ushort)(decrypted[0] | (decrypted[1] << 8));
                uint nonce = (uint)(decrypted[2] | (decrypted[3] << 8) | (decrypted[4] << 16) | (decrypted[5] << 24));
                byte flags = decrypted[6];
                byte cmdType = (byte)(flags & 0x7F);
                bool hasSentTime = (flags & 0x80) != 0;

                if (peer.PacketCount <= 30 || cmdType > 5)
                {
                    Log($"  [DECRYPT] peerID=0x{peerID:X4} nonce=0x{nonce:X8} flags=0x{flags:X2} cmd={cmdType} sentTime={hasSentTime}");
                    if (decrypted.Length > 7)
                        Log($"  [BODY] {Hex(decrypted, 7, Math.Min(32, decrypted.Length - 7))}");
                }

                // Detect KeyCheck: reliable command with game data
                if (cmdType == 0x06 || cmdType == 0x86)  // SEND_RELIABLE
                {
                    Log($"  [RELIABLE] cmd=0x{cmdType:X2} bodyLen={decrypted.Length - 7}");
                    if (decrypted.Length > 11)
                    {
                        // ENet SEND_RELIABLE body: [2B dataLen BE][data...]
                        int dataLen = (decrypted[7] << 8) | decrypted[8];
                        Log($"  [DATA] len={dataLen} first4={Hex(decrypted, 9, Math.Min(4, decrypted.Length - 9))}");
                    }
                }
            }
        }

        if (!peer.Connected)
        {
            peer.Connected = true;
            peer.OutgoingPeerID = 1;
            Log($"  [HANDSHAKE] ECHO-ONLY mode");
            EnsureClientInfo(peer);
        }

        // =================================================================
        // VERIFY_CONNECT: [4B header][Double CFB encrypted payload]
        // Header = 4 bytes consumed by client (param_1+0x146 = 4)
        // Payload plaintext: [2B peerID LE][4B CRC nonce][1B flags][body...]
        //
        // CRC nonce = ~CRC32 over struct:
        //   init = (byte[8] | 0xFFFFFF00) ^ 0xB1F740B4, byte[8]=0
        //   feed: byte[9]=0, bytes[0..7]={1,0,0,0,0,0,0,0}, 8x 0xFF
        //   nonce = ~crc = 0x8DFE1964
        //
        // FUN_140577f10 calls (*DAT_1418dfd10)(~crc) before returning.
        // If that's htonl: returned value = byte-swapped = 0x6419FE8D
        //   → client reads LE int → need BE bytes [8D FE 19 64]
        // If that's identity: returned value = 0x8DFE1964
        //   → client reads LE int → need LE bytes [64 19 FE 8D]
        //
        // We try BOTH to determine which is correct.
        // =================================================================
        {
            uint nonce = 0x8DFE1964;
            // Standard ENet VERIFY_CONNECT body = 36 bytes (big-endian):
            //   [2B outgoingPeerID]
            //   [1B incomingSessionID]
            //   [1B outgoingSessionID]
            //   [4B mtu]
            //   [4B windowSize]
            //   [4B channelCount]
            //   [4B incomingBandwidth]
            //   [4B outgoingBandwidth]
            //   [4B packetThrottleInterval]
            //   [4B packetThrottleAcceleration]
            //   [4B packetThrottleDeceleration]
            var verifyBody = new byte[36];
            {
                int o = 0;
                WriteBE16(verifyBody, o, 0); o += 2;     // outPeerID = 0 (server's peer ID for this client)
                verifyBody[o++] = 0xFF;                   // incomingSessionID
                verifyBody[o++] = 0xFF;                   // outgoingSessionID
                WriteBE32(verifyBody, o, 996); o += 4;    // MTU
                WriteBE32(verifyBody, o, 32768); o += 4;  // windowSize
                WriteBE32(verifyBody, o, 1); o += 4;      // channelCount (LoL uses 1 channel typically)
                WriteBE32(verifyBody, o, 0); o += 4;      // incomingBandwidth
                WriteBE32(verifyBody, o, 0); o += 4;      // outgoingBandwidth
                WriteBE32(verifyBody, o, 5000); o += 4;   // packetThrottleInterval (ms)
                WriteBE32(verifyBody, o, 2); o += 4;      // packetThrottleAcceleration
                WriteBE32(verifyBody, o, 2); o += 4;      // packetThrottleDeceleration
            }

            // =================================================================
            // CONN[0x146] = 0 → NO header prefix! Send raw encrypted data.
            // CRC includes payload! FUN_1405725f0 copies body to param_1+9
            // and updates param_1[0x52] BEFORE calling FUN_140577f10.
            // =================================================================

            // CRC WITHOUT payload (in case payload is NOT included)
            uint nonceNoPL = nonce;  // 0x8DFE1964

            // CRC WITH payload
            byte peerLo = 0, peerHi = 0;
            uint crc2 = ((uint)peerLo | 0xFFFFFF00u) ^ 0xB1F740B4u;
            crc2 = CrcByte(crc2, peerHi);
            byte[] localC8 = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            foreach (var b in localC8) crc2 = CrcByte(crc2, b);
            for (int i = 0; i < 8; i++) crc2 = CrcByte(crc2, 0xFF);
            foreach (var b in verifyBody) crc2 = CrcByte(crc2, b);
            uint nonceWithPL = ~crc2;
            Log($"  [CRC] noPL=0x{nonceNoPL:X8} withPL=0x{nonceWithPL:X8}");

            // CONFIRMED FORMAT: [4B preamble][Double CFB encrypted payload]
            // Preamble = any 4 bytes (skipped by client at offset from CONN+0x144)
            // CRC nonce = htonl(~CRC32_with_payload) = WriteBE32
            // CRC includes the VERIFY_CONNECT body as payload
            {
                var pt = new byte[2 + 4 + 1 + verifyBody.Length]; // 39B
                WriteLE16(pt, 0, 0);           // peerID = 0
                WriteBE32(pt, 2, nonceWithPL); // nonce in BE = htonl(~crc_with_payload)
                pt[6] = 0x03;                  // flags = VERIFY_CONNECT
                Array.Copy(verifyBody, 0, pt, 7, verifyBody.Length);
                var enc = DoubleCfbEncrypt(pt);

                // 4B preamble (use ConnectToken, but any value works)
                var pkt = new byte[4 + enc.Length]; // 43B
                WriteBE32(pkt, 0, peer.ConnectToken);
                Array.Copy(enc, 0, pkt, 4, enc.Length);
                Log($"  [VERIFY_CONNECT] nonce=0x{nonceWithPL:X8} BE+PL ({pkt.Length}B)");
                Send(pkt, peer);
            }

            peer.VerifySeqNo++;
        }

        // After handshake settles (packet 10+), send KeyCheck
        if (!peer.GameInitSent && peer.PacketCount >= 10)
        {
            peer.GameInitSent = true;
            Log($"  [GAME] Sending KeyCheck on reliable channel");

            // Build KeyCheck as ENet SEND_RELIABLE
            // Format: [4B token][ENet cmd header][KeyCheck payload]
            // ENet SEND_RELIABLE: [1B cmd=0x86(RELIABLE|SENT_TIME)][1B channel=0][2B seq BE][2B dataLen BE][payload]
            // KeyCheck opcode: 0x64000000 (LE) = opcode 100
            var keyCheck = new byte[4 + 6 + 12]; // token(4) + cmd header(6) + keycheck payload(12)
            WriteBE32(keyCheck, 0, peer.ConnectToken);
            keyCheck[4] = 0x86; // SEND_RELIABLE | SENT_TIME
            keyCheck[5] = 0x00; // channel 0
            WriteBE16(keyCheck, 6, 1); // seqNo
            WriteBE16(keyCheck, 8, 12); // dataLen = 12 bytes

            // KeyCheck payload: [4B opcode LE][1B playerNo][3B padding][4B checkId]
            keyCheck[10] = 0x64; // opcode 100 (LE low byte)
            keyCheck[11] = 0x00;
            keyCheck[12] = 0x00;
            keyCheck[13] = 0x00;
            keyCheck[14] = 0x00; // playerNo = 0
            keyCheck[15] = 0x00;
            keyCheck[16] = 0x00;
            keyCheck[17] = 0x00;
            // checkId = the Blowfish key checksum
            WriteBE32(keyCheck, 18, 0); // checkId = 0 for now

            Log($"  [KEYCHECK] {keyCheck.Length}B plaintext");
            Send(keyCheck, peer);

            // Also try as echo-sized packet
            var kcPadded = new byte[data.Length - 8]; // same size as last echo
            Array.Copy(keyCheck, 0, kcPadded, 0, Math.Min(keyCheck.Length, kcPadded.Length));
            Log($"  [KEYCHECK-PAD] {kcPadded.Length}B");
            Send(kcPadded, peer);
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
        // Based on Ghidra analysis of FUN_140577f10 + FUN_140588f70:
        // The CRC is computed over a STACK struct, NOT the packet payload.
        //
        // Stack struct (param_1 of FUN_140577f10):
        //   byte[8..9]  = first 2 bytes of local_c0 = {0, 0} (when conn+0x138 != 0)
        //   byte[0..7]  = local_c8 = *(conn+0x138) = 1 as int64 LE
        //   offset 0x18 = local_b0 = 0xFFFFFFFFFFFFFFFF
        //   payload_len = 0 (no payload in CRC)
        //
        // Processing order: init(byte[8]), byte[9], byte[0..7], local_res10[0..7]

        byte peerLo = 0; // byte[8] of stack struct = 0
        byte peerHi = 0; // byte[9] of stack struct = 0
        uint crc = ((uint)peerLo | 0xFFFFFF00u) ^ 0xB1F740B4u;
        crc = CrcByte(crc, peerHi);

        // bytes[0..7] = local_c8 = 1 as int64 LE
        byte[] localC8 = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        for (int i = 0; i < 8; i++)
            crc = CrcByte(crc, localC8[i]);

        // local_res10 = 0xFFFFFFFFFFFFFFFF
        for (int i = 0; i < 8; i++)
            crc = CrcByte(crc, 0xFF);

        // NO payload in CRC (payloadLen = 0)
        uint crcNonce = ~crc;
        Log($"  [CRC] nonce=0x{crcNonce:X8} (peerLo=0, peerHi=0, localC8=1, res10=0xFF*8)");

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
        // Same CRC as all packets: based on stack struct, not packet content
        ushort peerID = peer.PeerId;
        byte flags = 0x05; // PING, no timestamp

        uint crc = (0xFFFFFF00u) ^ 0xB1F740B4u; // peerLo=0
        crc = CrcByte(crc, 0); // peerHi=0
        byte[] localC8 = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        for (int i = 0; i < 8; i++) crc = CrcByte(crc, localC8[i]);
        for (int i = 0; i < 8; i++) crc = CrcByte(crc, 0xFF); // local_res10
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
    /// <summary>Swap byte order of each uint32 half (BE C# → LE native convention)</summary>
    private static void SwapKeystream(byte[] ks)
    {
        (ks[0], ks[3]) = (ks[3], ks[0]);
        (ks[1], ks[2]) = (ks[2], ks[1]);
        (ks[4], ks[7]) = (ks[7], ks[4]);
        (ks[5], ks[6]) = (ks[6], ks[5]);
    }

    private byte[] CfbEncrypt(byte[] plaintext)
    {
        var result = (byte[])plaintext.Clone();
        var feedback = new byte[8]; // IV = zeros
        int fullBlocks = plaintext.Length / 8;

        for (int block = 0; block < fullBlocks; block++)
        {
            int i = block * 8;
            // No swap needed: BF reads feedback in BE (same as client's CONCAT31),
            // and outputs keystream in BE (byte-by-byte XOR matches client's uint32 XOR).
            var keystream = _cipher.EncryptBlock(feedback);
            for (int j = 0; j < 8; j++)
                result[i + j] = (byte)(plaintext[i + j] ^ keystream[j]);

            Array.Copy(result, i, feedback, 0, 8);
        }

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
    /// Double CFB decrypt: CFB decrypt → reverse → CFB decrypt (both IV=0).
    /// Inverse of DoubleCfbEncrypt.
    /// </summary>
    private byte[] DoubleCfbDecrypt(byte[] ciphertext)
    {
        var result = CfbDecrypt(ciphertext);
        Array.Reverse(result);
        result = CfbDecrypt(result);
        return result;
    }

    /// <summary>
    /// Decrypt with Blowfish CFB using fresh IV=zeros (per-packet).
    /// </summary>
    private byte[] CfbDecrypt(byte[] ciphertext)
    {
        var result = (byte[])ciphertext.Clone();
        var feedback = new byte[8]; // IV = zeros
        int fullBlocks = ciphertext.Length / 8;

        for (int block = 0; block < fullBlocks; block++)
        {
            int i = block * 8;
            var keystream = _cipher.EncryptBlock(feedback);
            Array.Copy(ciphertext, i, feedback, 0, 8);
            for (int j = 0; j < 8; j++)
                result[i + j] = (byte)(ciphertext[i + j] ^ keystream[j]);
        }

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
    private static string Hex(byte[] d, int offset, int count) => BitConverter.ToString(d, offset, Math.Min(count, d.Length - offset));

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
