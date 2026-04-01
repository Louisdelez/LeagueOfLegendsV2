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

        // Send VERIFY_CONNECT with SINGLE CFB (confirmed by decrypt analysis)
        // The client uses SINGLE CFB from byte 12 (after 8B LNPBlob + 4B token)
        // For server->client, format is just [single CFB encrypted ENet data]
        // The ENet header: [4B sessionID=0][2B peerID|flags][2B sentTime][commands...]
        SendVerifyConnect(peer);

        // Also echo for comparison
        if (data.Length > 8)
        {
            var echo = new byte[data.Length - 8];
            Array.Copy(data, 8, echo, 0, echo.Length);
            Send(echo, peer);
        }
        else if (!peer.GameInitSent)
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

        // --- ALSO send standard ENet VERIFY_CONNECT with SINGLE CFB ---
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
            Log($"  [VC-SINGLE] ENet single CFB ({singleEnc.Length}B): enc={Hex(singleEnc, 20)}");
            Send(singleEnc, peer);
        }

        // Also send the double CFB version (original)
        var encrypted = DoubleCfbEncrypt(plaintext);
        Log($"  [VC-DOUBLE] CRC+dblCFB ({encrypted.Length}B): enc={Hex(encrypted, 20)}");
        Send(encrypted, peer);

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
        var result = new byte[plaintext.Length];
        var feedback = new byte[8]; // IV = zeros

        for (int i = 0; i < plaintext.Length; i += 8)
        {
            var keystream = _cipher.EncryptBlock(feedback);
            int blockLen = Math.Min(8, plaintext.Length - i);
            for (int j = 0; j < blockLen; j++)
                result[i + j] = (byte)(plaintext[i + j] ^ keystream[j]);

            // CFB feedback: ciphertext becomes next IV
            Array.Copy(result, i, feedback, 0, blockLen);
            if (blockLen < 8) Array.Clear(feedback, blockLen, 8 - blockLen);
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
        // Reverse processed blocks
        int processed = (result.Length / 8) * 8;
        Array.Reverse(result, 0, processed);
        // Pass 2: CFB encrypt
        result = CfbEncrypt(result);
        return result;
    }

    /// <summary>
    /// Decrypt with Blowfish CFB using fresh IV=zeros (per-packet).
    /// </summary>
    private byte[] CfbDecrypt(byte[] ciphertext)
    {
        var result = new byte[ciphertext.Length];
        var feedback = new byte[8]; // IV = zeros

        for (int i = 0; i < ciphertext.Length; i += 8)
        {
            var keystream = _cipher.EncryptBlock(feedback);
            int blockLen = Math.Min(8, ciphertext.Length - i);

            // Save ciphertext for feedback BEFORE XOR
            var nextFeedback = new byte[8];
            Array.Copy(ciphertext, i, nextFeedback, 0, blockLen);

            for (int j = 0; j < blockLen; j++)
                result[i + j] = (byte)(ciphertext[i + j] ^ keystream[j]);

            feedback = nextFeedback;
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
