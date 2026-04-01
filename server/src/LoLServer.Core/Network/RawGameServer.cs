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
/// PROTOCOL (confirmed by Ghidra static analysis, 1 April 2026):
///
/// Encryption: Blowfish CFB mode (64-bit segments), IV=zeros initially
/// The ENTIRE packet (header + commands) is encrypted.
///
/// Plaintext format (LENet Season 12, big-endian):
///   [4B SessionID BE][2B PeerID|TimeSentFlag BE][2B TimeSent BE][ENet commands...]
///
/// The Blowfish CFB state is persistent between packets in each direction.
/// First packet uses IV=0, subsequent packets continue the CFB chain.
/// </summary>
public class RawGameServer : IGameServer, IDisposable
{
    private UdpClient? _socket;
    private readonly int _port;
    private readonly GameConfig _config;
    private readonly PacketHandler _handler;
    private readonly Dictionary<ushort, ClientInfo> _clients = new();
    private readonly ConcurrentDictionary<string, PeerInfo> _peers = new();
    private readonly byte[] _blowfishKey;
    private bool _running;
    private ushort _nextPeerId;
    private uint _sessionId = 0xDEADBEEF;

    public event Action<string>? OnLog;
    public IReadOnlyDictionary<ushort, ClientInfo> Clients => _clients;

    public RawGameServer(int port, GameConfig config)
    {
        _port = port;
        _config = config;
        _handler = new PacketHandler(config, this);
        _blowfishKey = Convert.FromBase64String(config.BlowfishKey);
    }

    public void Start()
    {
        Log("=== LoL Private Server (Blowfish CFB Mode) ===");
        Log($"Port: {_port}");
        Log($"Blowfish Key: {_config.BlowfishKey} ({_blowfishKey.Length} bytes)");
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
                DecryptIV = new byte[8], // IV starts at zero
                EncryptIV = new byte[8], // IV starts at zero
            };
            Log($"[NEW PEER] {remoteKey} → PeerId={p.PeerId}");
            return p;
        });
        peer.PacketCount++;

        if (data.Length < 8) return;

        bool verbose = peer.PacketCount <= 10;

        // Decrypt the packet with Blowfish CFB
        byte[] decrypted = BlowfishCfbDecrypt(data, peer.DecryptIV);

        if (verbose)
        {
            Log($"[{remoteKey}] #{peer.PacketCount} {data.Length}B");
            Log($"  Raw: {Hex(data, 24)}");
            Log($"  Dec: {Hex(decrypted, 24)}");
        }

        // Parse LENet Season 12 header (big-endian)
        uint sessID = ReadBE32(decrypted, 0);
        ushort peerIDraw = ReadBE16(decrypted, 4);
        bool hasSentTime = (peerIDraw & 0x8000) != 0;
        ushort peerID = (ushort)(peerIDraw & 0x7FFF);
        int off = 6;
        ushort sentTime = 0;
        if (hasSentTime) { sentTime = ReadBE16(decrypted, off); off += 2; }

        if (verbose)
            Log($"  Header: SessID=0x{sessID:X8} PeerID=0x{peerID:X4} SentTime={sentTime}");

        // Parse ENet commands
        if (off + 4 > decrypted.Length) return;

        byte cmdByte = decrypted[off];
        byte channel = decrypted[off + 1];
        ushort seqNo = ReadBE16(decrypted, off + 2);
        int cmd = cmdByte & 0x0F;
        int flags = (cmdByte >> 4) & 0x0F;

        if (verbose)
            Log($"  Cmd=0x{cmdByte:X2}(type={cmd}) Ch={channel} Seq={seqNo}");

        switch (cmd)
        {
            case 2: // CONNECT
                HandleConnect(decrypted, off, peer, peerID, sentTime);
                break;
            case 1: // ACK
                if (verbose) Log($"  [ACK]");
                break;
            case 5: // PING
                HandlePing(peer, sentTime);
                break;
            case 6: // SEND_RELIABLE
                HandleReliable(decrypted, off, peer);
                break;
            case 4: // DISCONNECT
                Log($"  [DISCONNECT]");
                break;
            default:
                if (verbose) Log($"  [Unknown cmd {cmd}]");
                // Send VERIFY_CONNECT anyway for the first few packets
                if (peer.PacketCount <= 5 && !peer.Connected)
                    SendVerifyConnect(peer, 0);
                break;
        }
    }

    private void HandleConnect(byte[] dec, int cmdOff, PeerInfo peer, ushort clientPeerID, ushort sentTime)
    {
        if (cmdOff + 4 + 40 > dec.Length)
        {
            Log($"  [CONNECT] Too short, sending VERIFY anyway");
            SendVerifyConnect(peer, sentTime);
            return;
        }

        int body = cmdOff + 4;
        ushort outPeerID = ReadBE16(dec, body);
        ushort mtu = ReadBE16(dec, body + 2);
        uint winSize = ReadBE32(dec, body + 4);
        uint chanCount = ReadBE32(dec, body + 8);

        Log($"  [CONNECT] OutPeerID={outPeerID} MTU={mtu} Win={winSize} Chan={chanCount}");

        peer.OutgoingPeerID = outPeerID;
        peer.Connected = true;

        SendVerifyConnect(peer, sentTime);
        EnsureClientInfo(peer);
    }

    private void SendVerifyConnect(PeerInfo peer, ushort clientSentTime)
    {
        // Build plaintext VERIFY_CONNECT in LENet Season 12 big-endian
        var plain = new byte[8 + 4 + 36]; // header + cmd_header + verify_body = 48 bytes

        int off = 0;
        // LENet header
        WriteBE32(plain, off, _sessionId); off += 4;
        WriteBE16(plain, off, (ushort)(peer.PeerId | 0x8000)); off += 2; // PeerID | TimeSent flag
        WriteBE16(plain, off, (ushort)(Environment.TickCount & 0xFFFF)); off += 2;

        // ENet VERIFY_CONNECT command
        plain[off] = 0x83; // cmd=3 (VERIFY_CONNECT) | flag 0x80 (SENT_TIME)
        plain[off + 1] = 0xFF; // channel = 0xFF
        WriteBE16(plain, off + 2, 1); // reliableSeqNo
        off += 4;

        // VERIFY_CONNECT body (Season 12, big-endian)
        WriteBE16(plain, off, peer.PeerId); off += 2;      // OutgoingPeerID
        WriteBE16(plain, off, 996); off += 2;               // MTU
        WriteBE32(plain, off, 32768); off += 4;             // WindowSize
        WriteBE32(plain, off, 32); off += 4;                // ChannelCount
        WriteBE32(plain, off, 0); off += 4;                 // IncomingBandwidth
        WriteBE32(plain, off, 0); off += 4;                 // OutgoingBandwidth
        WriteBE32(plain, off, 32); off += 4;                // PacketThrottleInterval
        WriteBE32(plain, off, 2); off += 4;                 // PacketThrottleAcceleration
        WriteBE32(plain, off, 2); off += 4;                 // PacketThrottleDeceleration

        Log($"  Plaintext VERIFY: {Hex(plain, 24)}");

        // Encrypt with Blowfish CFB
        byte[] encrypted = BlowfishCfbEncrypt(plain, peer.EncryptIV);

        Log($"  Encrypted VERIFY: {Hex(encrypted, 24)} ({encrypted.Length}B)");

        try
        {
            _socket!.Send(encrypted, encrypted.Length, peer.Remote);
            Log($"  [SENT] VERIFY_CONNECT {encrypted.Length}B");
        }
        catch (Exception ex) { Log($"  [ERROR] {ex.Message}"); }
    }

    private void HandlePing(PeerInfo peer, ushort sentTime)
    {
        // Send ACK
        var plain = new byte[8 + 8]; // header + ACK command
        int off = 0;
        WriteBE32(plain, off, _sessionId); off += 4;
        WriteBE16(plain, off, (ushort)(peer.OutgoingPeerID | 0x8000)); off += 2;
        WriteBE16(plain, off, (ushort)(Environment.TickCount & 0xFFFF)); off += 2;
        plain[off] = 0x81; // ACK | SENT_TIME
        plain[off + 1] = 0xFF;
        WriteBE16(plain, off + 2, 0);
        WriteBE16(plain, off + 4, sentTime);

        byte[] enc = BlowfishCfbEncrypt(plain, peer.EncryptIV);
        try { _socket!.Send(enc, enc.Length, peer.Remote); }
        catch { }
    }

    private void HandleReliable(byte[] dec, int cmdOff, PeerInfo peer)
    {
        if (cmdOff + 6 > dec.Length) return;
        byte ch = dec[cmdOff + 1];
        ushort seqNo = ReadBE16(dec, cmdOff + 2);
        ushort dataLen = ReadBE16(dec, cmdOff + 4);
        Log($"  [RELIABLE] Ch={ch} Seq={seqNo} Len={dataLen}");

        // Send ACK
        // TODO: route to game logic
    }

    // ========================================================================
    //  BLOWFISH CFB ENCRYPTION
    // ========================================================================

    private byte[] BlowfishCfbEncrypt(byte[] plaintext, byte[] iv)
    {
        var bf = new BlowFish(Convert.FromBase64String(_config.BlowfishKey));
        var result = new byte[plaintext.Length];
        var feedback = (byte[])iv.Clone();

        for (int i = 0; i < plaintext.Length; i += 8)
        {
            // Encrypt the feedback (IV for first block)
            var keystream = bf.EncryptBlock(feedback);

            int blockLen = Math.Min(8, plaintext.Length - i);
            for (int j = 0; j < blockLen; j++)
            {
                result[i + j] = (byte)(plaintext[i + j] ^ keystream[j]);
            }

            // CFB feedback: use ciphertext as next IV
            Array.Copy(result, i, feedback, 0, blockLen);
            if (blockLen < 8)
                Array.Clear(feedback, blockLen, 8 - blockLen);
        }

        // Update the persistent IV
        Array.Copy(feedback, iv, 8);

        return result;
    }

    private byte[] BlowfishCfbDecrypt(byte[] ciphertext, byte[] iv)
    {
        var bf = new BlowFish(Convert.FromBase64String(_config.BlowfishKey));
        var result = new byte[ciphertext.Length];
        var feedback = (byte[])iv.Clone();

        for (int i = 0; i < ciphertext.Length; i += 8)
        {
            var keystream = bf.EncryptBlock(feedback);

            int blockLen = Math.Min(8, ciphertext.Length - i);

            // Save ciphertext for feedback BEFORE decrypting
            var nextFeedback = new byte[8];
            Array.Copy(ciphertext, i, nextFeedback, 0, blockLen);

            for (int j = 0; j < blockLen; j++)
            {
                result[i + j] = (byte)(ciphertext[i + j] ^ keystream[j]);
            }

            feedback = nextFeedback;
        }

        // Update persistent IV
        Array.Copy(feedback, iv, 8);

        return result;
    }

    // ========================================================================
    //  HELPERS
    // ========================================================================

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
        public byte[] DecryptIV { get; set; } = new byte[8];
        public byte[] EncryptIV { get; set; } = new byte[8];
    }
}
