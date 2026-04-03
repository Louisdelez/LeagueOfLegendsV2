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

        // Decrypt: [8B LNPBlob][encrypted: [2B peerID][4B nonce][1B flags][body...]]
        // Everything after LNPBlob is Double-CFB encrypted
        if (data.Length > 8)
        {
            int encLen = data.Length - 8;
            byte[] payload = new byte[encLen];
            Array.Copy(data, 8, payload, 0, encLen);

            byte[] decrypted = DoubleCfbDecrypt(payload);

            // After decrypt: [2B peerID][4B nonce][1B flags][body...]
            if (decrypted.Length >= 7)
            {
                ushort peerID = (ushort)(decrypted[0] | (decrypted[1] << 8));
                uint nonce = (uint)(decrypted[2] | (decrypted[3] << 8) | (decrypted[4] << 16) | (decrypted[5] << 24));
                byte flags = decrypted[6];
                byte cmdType = (byte)(flags & 0x7F);
                bool hasSentTime = (flags & 0x80) != 0;

                if (peer.PacketCount <= 100 || cmdType > 10)
                {
                    int bodyLen = decrypted.Length - 7;
                    Log($"  [DECRYPT] peerID=0x{peerID:X4} nonce=0x{nonce:X8} cmd={cmdType}(0x{cmdType:X2}) sentTime={hasSentTime} bodyLen={bodyLen}");
                    if (bodyLen > 0)
                        Log($"  [BODY] {Hex(decrypted, 7, Math.Min(48, bodyLen))}");
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
        // Store raw payload (after LNPBlob) for replay
        if (data.Length > 8)
        {
            peer.LastPayload = new byte[data.Length - 8];
            Array.Copy(data, 8, peer.LastPayload, 0, data.Length - 8);
        }
        // ALWAYS echo back to keep recvfrom unblocked.
        if (data.Length > 12)
        {
            int echoLen = data.Length - 8;
            var echo = new byte[echoLen];
            Array.Copy(data, 8, echo, 0, echoLen);
            Send(echo, peer);
        }

        // DISABLED: test without CAFE to see if timeout is from our packets or internal
        if (false && !peer.GameInitSent && peer.PacketCount >= 10)
        {
            peer.GameInitSent = true;
            Log($"  [GAME] Sending KeyCheck via CRC-format packet");

            // ===== SEND RELIABLE KeyCheck =====
            // ENet SEND_RELIABLE body after CRC flags byte:
            //   [1B channelID][2B reliableSeqNo BE][2B dataLen BE][data...]
            // KeyCheck: 32 bytes packet on handshake channel
            // [1B action=0][3B pad][4B clientID LE][8B playerID LE][4B versionNo LE][8B checksum LE][4B pad]
            // Checksum = BF_encrypt(playerID bytes)
            var keyCheckData = new byte[32];
            keyCheckData[0] = 0x00; // action = 0 (response)
            // pad [1-3] = 0
            WriteLE32(keyCheckData, 4, 0); // clientID = 0
            // playerID at offset 8 (8 bytes LE) = 1
            keyCheckData[8] = 0x01;
            // versionNo at offset 16 = 0
            // checksum at offset 20 = BF_encrypt(playerID)
            var playerIdBytes = new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            var encrypted = _cipher.EncryptBlock(playerIdBytes);
            Array.Copy(encrypted, 0, keyCheckData, 20, 8);

            var reliableBody = new byte[1 + 2 + 2 + keyCheckData.Length]; // channel(1) + seq(2) + len(2) + data
            reliableBody[0] = 0x00; // channel 0 = handshake
            WriteBE16(reliableBody, 1, peer.ReliableSeqNo++); // seqNo
            WriteBE16(reliableBody, 3, (ushort)keyCheckData.Length); // dataLen = 32
            Array.Copy(keyCheckData, 0, reliableBody, 5, keyCheckData.Length);

            // Try VERIFY_CONNECT (cmd=3) with KeyCheck in body
            // In 16.6, the KeyCheck might be embedded in VERIFY_CONNECT response
            {
                // Standard ENet VERIFY_CONNECT body (36 bytes, big-endian)
                var vcBody = new byte[36];
                WriteBE16(vcBody, 0, 0);      // outPeerID
                vcBody[2] = 0xFF;             // incomingSessionID
                vcBody[3] = 0xFF;             // outgoingSessionID
                WriteBE32(vcBody, 4, 996);    // MTU
                WriteBE32(vcBody, 8, 32768);  // windowSize
                WriteBE32(vcBody, 12, 1);     // channelCount
                WriteBE32(vcBody, 16, 0);     // inBandwidth
                WriteBE32(vcBody, 20, 0);     // outBandwidth
                WriteBE32(vcBody, 24, 5000);  // throttleInterval
                WriteBE32(vcBody, 28, 2);     // throttleAccel
                WriteBE32(vcBody, 32, 2);     // throttleDecel
                SendCrcPacket(peer, 0x03, vcBody); // cmd=3 = VERIFY_CONNECT
                Log($"  [VC] sent VERIFY_CONNECT cmd=0x03, {vcBody.Length}B");
            }

            // NEW APPROACH: capture client's data and echo it back via CAFE
            // The server stores raw client payloads and sends them back
            // This ensures the game receives data in its OWN format
            if (peer.LastPayload != null && peer.LastPayload.Length > 0)
            {
                // Send client's own 36B payload back (after stripping LNPBlob+header)
                // The hook will re-encrypt with game's BF and fix CRC
                var echoPayload = peer.LastPayload;
                // We need to send the INNER data (after 4B header) as the body
                // Format for CAFE: [4B nonce placeholder][1B flags][body]
                // The client's data after 4B header is already in the right format
                if (echoPayload.Length >= 4)
                {
                    // Send as plaintext (hook will encrypt+CRC)
                    // The flags byte from client's data will be used
                    var innerData = new byte[echoPayload.Length - 4];
                    Array.Copy(echoPayload, 4, innerData, 0, innerData.Length);
                    // Prepend nonce placeholder
                    var plaintext = new byte[((4 + innerData.Length + 7) / 8) * 8]; // pad to 8
                    WriteLE32(plaintext, 0, 0xDEADBEEF);
                    Array.Copy(innerData, 0, plaintext, 4, innerData.Length);

                    // Build CAFE packet with 4B header
                    var packet = new byte[2 + 4 + plaintext.Length];
                    packet[0] = 0xCA; packet[1] = 0xFE;
                    // Header = first 4B of client payload (connection token)
                    Array.Copy(echoPayload, 0, packet, 2, 4);
                    Array.Copy(plaintext, 0, packet, 6, plaintext.Length);
                    Send(packet, peer);
                    Log($"  [CAFE-REPLAY] echoed client data, inner={innerData.Length}B total={packet.Length}B");
                }
            }

            // Also send KeyCheck with cmd=0x06
            SendCrcPacket(peer, 0x06, reliableBody);
            Log($"  [KC-06] cmd=0x06, {reliableBody.Length}B");
        }
    }

    /// <summary>
    /// Send a VERIFY_CONNECT packet using the confirmed Ghidra format.
    ///
    /// Plaintext: [2B peerID LE][4B CRC_NONCE BE][1B flags][36B ENet VERIFY_CONNECT body BE]
    /// Encrypted: Double CFB (encrypt → reverse → encrypt), Blowfish IV=0
    /// Sent: raw encrypted bytes, no prefix
    /// </summary>
    // Old SendVerifyConnect, ScheduleGameInit, SendPing removed.
    // Now using SendCrcPacket for all server→client communication.
    // The hook DLL fixes CRC nonces automatically.

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
            var keystream = _cipher.EncryptBlock(feedback);
            for (int j = 0; j < 8; j++)
                result[i + j] = (byte)(plaintext[i + j] ^ keystream[j]);
            // Feedback = ciphertext block (for encrypt: result)
            Array.Copy(result, i, feedback, 0, 8);
        }
        // Remaining bytes are NOT encrypted (sent in cleartext per Ghidra analysis)

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
    /// Alternative Double CFB decrypt using BF_decrypt for keystream.
    /// If the client's SEND path uses BF_decrypt instead of BF_encrypt.
    /// </summary>
    private byte[] DoubleCfbDecryptAlt(byte[] ciphertext)
    {
        var result = CfbDecryptAlt(ciphertext);
        Array.Reverse(result);
        result = CfbDecryptAlt(result);
        return result;
    }

    private byte[] CfbDecryptAlt(byte[] ciphertext)
    {
        var result = (byte[])ciphertext.Clone();
        var feedback = new byte[8];
        int fullBlocks = ciphertext.Length / 8;
        for (int block = 0; block < fullBlocks; block++)
        {
            int i = block * 8;
            var keystream = _cipher.DecryptBlock(feedback); // BF_DECRYPT instead of BF_ENCRYPT
            Array.Copy(ciphertext, i, feedback, 0, 8);
            for (int j = 0; j < 8; j++)
                result[i + j] = (byte)(ciphertext[i + j] ^ keystream[j]);
        }
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
            // Save ciphertext block for feedback BEFORE XOR
            Array.Copy(ciphertext, i, feedback, 0, 8);
            for (int j = 0; j < 8; j++)
                result[i + j] = (byte)(ciphertext[i + j] ^ keystream[j]);
        }
        // Remaining bytes are NOT encrypted (pass through per Ghidra analysis)

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

    /// <summary>
    /// Send a packet in the CRC-format that the hook DLL can fix.
    /// Format: [2B magic 0xCAFE] + Double-CFB encrypted plaintext:
    ///   [2B peerID LE=0][4B CRC nonce placeholder][1B flags=cmdType][body...]
    /// The hook will strip the magic marker, fix CRC nonce, and deliver.
    /// </summary>
    private void SendCrcPacket(PeerInfo peer, byte cmdType, byte[] body)
    {
        // Format discovered from Ghidra analysis of FUN_140588f70:
        // [4B header (unencrypted, skipped by conn+0x144=4)]
        // [Double-CFB encrypted: [4B CRC nonce][1B flags][body...]]
        //
        // The hook will:
        // 1. Strip CAFE prefix
        // 2. Skip 4B header
        // 3. Decrypt bytes 4+ with game's BF
        // 4. Compute CRC, patch nonce
        // 5. Re-encrypt bytes 4+

        // Send PLAINTEXT with CAFE prefix. The hook will encrypt using game's own BF.
        // Format: [2B CAFE][4B header][PLAINTEXT: [4B nonce placeholder][1B flags][body]]
        // Pad plaintext to multiple of 8 bytes
        int ptRawLen = 4 + 1 + body.Length;
        int ptPaddedLen = (ptRawLen + 7) & ~7;
        var plaintext = new byte[ptPaddedLen];
        WriteLE32(plaintext, 0, 0xDEADBEEF); // placeholder nonce (hook will compute)
        plaintext[4] = cmdType;
        if (body.Length > 0)
            Array.Copy(body, 0, plaintext, 5, body.Length);

        // NO encryption here! Send plaintext directly.
        var packet = new byte[2 + 4 + plaintext.Length];
        packet[0] = 0xCA;
        packet[1] = 0xFE;
        WriteLE16(packet, 2, 0); // peerID = 0
        packet[4] = 0; packet[5] = 0;
        Array.Copy(plaintext, 0, packet, 6, plaintext.Length);

        Log($"  [CRC-PKT] cmd=0x{cmdType:X2} body={body.Length}B pt={plaintext.Length}B total={packet.Length}B (PLAINTEXT)");
        Send(packet, peer);
    }

    private class PeerInfo
    {
        public IPEndPoint Remote { get; set; } = null!;
        public ushort PeerId { get; set; }
        public ushort OutgoingPeerID { get; set; }
        public bool Connected { get; set; }
        public int PacketCount { get; set; }
        public bool GameInitSent { get; set; }
        public ushort VerifySeqNo { get; set; } = 1;
        public ushort ReliableSeqNo { get; set; } = 1;
        public uint ConnectToken { get; set; }
        public byte[]? LastPayload { get; set; }
    }
}
