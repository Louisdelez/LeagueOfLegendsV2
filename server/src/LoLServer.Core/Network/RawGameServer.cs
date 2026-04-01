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
/// PROTOCOL (confirmed by Ghidra + packet capture analysis, April 2026):
///
/// Server → Client: Single Blowfish CFB, per-packet fresh IV=zeros.
///   Plaintext: [4B SessionID BE][2B PeerID|Flags BE][2B SentTime BE][ENet commands...]
///
/// Client → Server: 519-byte packets with format:
///   [4B LNPBlob magic 0x37AA0014][4B SessionID LE][payload...][2B footer]
///   The payload format is proprietary. We detect the client by LNPBlob magic.
///
/// Verified: BF_encrypt(zeros) bytes appear in the client packet header as key proof.
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
        Log("=== LoL Private Server (Blowfish CFB Mode) ===");
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

        if (verbose)
        {
            Log($"[CLIENT] #{peer.PacketCount} {data.Length}B LNPBlob sessID=0x{sessIdLE:X8}");
            Log($"  Header: {Hex(data, 16)}");
        }

        if (!peer.Connected)
        {
            // First connection - send VERIFY_CONNECT
            peer.Connected = true;
            peer.OutgoingPeerID = 0;
            Log($"  [HANDSHAKE] Sending VERIFY_CONNECT");
            SendVerifyConnect(peer);
            EnsureClientInfo(peer);

            // After VERIFY_CONNECT, immediately start sending game init
            // The client may not ACK explicitly in a format we can detect
            ScheduleGameInit(peer);
        }
        else if (peer.PacketCount <= 10)
        {
            // Client retransmitting - resend VERIFY_CONNECT
            if (verbose) Log($"  [RETRANSMIT] Re-sending VERIFY_CONNECT");
            SendVerifyConnect(peer);
        }
        else if (!peer.GameInitSent)
        {
            // Try sending game init data
            ScheduleGameInit(peer);
        }
    }

    private void SendVerifyConnect(PeerInfo peer)
    {
        // Build response with VERIFY_CONNECT + ACK bundled together
        // This matches Riot's server behavior (119B responses vs our previous 48B)
        //
        // Format: [8B header][VERIFY_CONNECT cmd(4+36)][ACK cmd(8)] = 56 bytes
        // Or possibly multiple ACKs and additional commands
        var plain = new byte[56]; // header(8) + VERIFY_CONNECT(40) + ACK(8)
        int off = 0;

        // LENet header (big-endian)
        WriteBE32(plain, off, _sessionId); off += 4;                              // SessionID
        WriteBE16(plain, off, (ushort)(peer.PeerId | 0x8000)); off += 2;          // PeerID | TimeSent flag
        WriteBE16(plain, off, (ushort)(Environment.TickCount & 0xFFFF)); off += 2; // SentTime

        // === VERIFY_CONNECT command (cmd=3 | 0x80 SENT_TIME flag) ===
        plain[off] = 0x83; off++;     // cmd | flags
        plain[off] = 0xFF; off++;     // channel
        WriteBE16(plain, off, peer.VerifySeqNo++); off += 2; // reliableSeqNo

        // VERIFY_CONNECT body
        WriteBE16(plain, off, peer.PeerId); off += 2;    // OutgoingPeerID
        WriteBE16(plain, off, 996); off += 2;              // MTU
        WriteBE32(plain, off, 32768); off += 4;            // WindowSize
        WriteBE32(plain, off, 32); off += 4;               // ChannelCount
        WriteBE32(plain, off, 0); off += 4;                // IncomingBandwidth
        WriteBE32(plain, off, 0); off += 4;                // OutgoingBandwidth
        WriteBE32(plain, off, 32); off += 4;               // PacketThrottleInterval
        WriteBE32(plain, off, 2); off += 4;                // PacketThrottleAcceleration
        WriteBE32(plain, off, 2); off += 4;                // PacketThrottleDeceleration

        // === ACK command for the client's CONNECT ===
        plain[off] = 0x81; off++;     // cmd=1 (ACK) | 0x80 flag
        plain[off] = 0xFF; off++;     // channel
        WriteBE16(plain, off, 0); off += 2;  // ackSeqNo (seq of the CONNECT we're ACKing)
        WriteBE16(plain, off, 0); off += 2;  // receivedSentTime
        WriteBE16(plain, off, (ushort)(Environment.TickCount & 0xFFFF)); off += 2; // receivedSentTime (or padding)

        // Encrypt with single Blowfish CFB (fresh IV=0 per packet)
        byte[] encrypted = CfbEncrypt(plain);

        Log($"  [{encrypted.Length}B] VERIFY_CONNECT + ACK");
        Log($"  Plain: {Hex(plain, 32)}");
        Log($"  Enc:   {Hex(encrypted, 32)}");

        Send(encrypted, peer);
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
        var plain = new byte[12]; // header(8) + PING cmd(4)
        int off = 0;

        WriteBE32(plain, off, _sessionId); off += 4;
        WriteBE16(plain, off, (ushort)(peer.PeerId | 0x8000)); off += 2;
        WriteBE16(plain, off, (ushort)(Environment.TickCount & 0xFFFF)); off += 2;

        // PING command (cmd=5)
        plain[off] = 0x05; off++;      // cmd=5 (PING), no flags
        plain[off] = 0xFF; off++;      // channel
        WriteBE16(plain, off, 0); off += 2; // seqNo

        byte[] encrypted = CfbEncrypt(plain);
        Send(encrypted, peer);
    }

    // ========================================================================
    //  BLOWFISH CFB ENCRYPTION (per-packet fresh IV=0)
    // ========================================================================

    /// <summary>
    /// Encrypt with Blowfish CFB using fresh IV=zeros (per-packet, no persistent state).
    /// This is confirmed to match what the client expects (verified via packet captures).
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
    }
}
