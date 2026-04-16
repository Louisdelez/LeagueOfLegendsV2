using System;
using System.Collections.Generic;
using System.Threading;
using LENet;
using LoLServer.Core.Config;
using LoLServer.Core.Protocol;
using LoLServer.Core.Protocol.Packets;
using Channel = LoLServer.Core.Protocol.Channel;

namespace LoLServer.Core.Network;

/// <summary>
/// ENet game server for League of Legends.
/// Uses LENet (LoL-compatible ENet) to handle client connections.
/// Supports auto-detection of protocol version by cycling through all known versions.
/// </summary>
public class PacketServer : IGameServer, IDisposable
{
    private Host? _server;
    private readonly int _port;
    private readonly GameConfig _config;
    private readonly PacketHandler _handler;
    private readonly Dictionary<ushort, ClientInfo> _clients = new();
    private bool _running;
    private bool _rawCaptureMode;
    private int _connectionAttempts;
    private DateTime _lastConnectionTime = DateTime.MinValue;

    // Protocol versions to try (note: LENet has typo "Seasson")
    // Modern LoL client (16.6+) sends 8-byte checksum headers
    private static readonly LENet.Version[] VersionsToTry =
    {
        LENet.Version.Seasson8_Server,   // Server: 0 send, 8 receive checksum ← modern client
        LENet.Version.Seasson34,         // Even newer
        LENet.Version.Seasson12,         // Newer
        LENet.Version.Patch420,          // 4-byte CRC32 both ways (old 4.20)
        LENet.Version.Seasson8_Client,   // Client: 8 send, 0 receive checksum
    };

    private int _versionIndex;
    private LENet.Version _currentVersion;
    private bool _autoDetect = true;

    public event Action<string>? OnLog;
    public event Action<byte[], int, string>? OnRawPacket;

    public PacketServer(int port, GameConfig config)
    {
        _port = port;
        _config = config;
        _currentVersion = VersionsToTry[0];
        _handler = new PacketHandler(config, this);
    }

    public void EnableRawCapture(bool enable = true)
    {
        _rawCaptureMode = enable;
    }

    public IReadOnlyDictionary<ushort, ClientInfo> Clients => _clients;

    public void Start()
    {
        Log($"=== LoL Private Server ===");
        Log($"Port: {_port}");
        Log($"Protocol: ChecksumSend={_currentVersion.ChecksumSizeSend} ChecksumRecv={_currentVersion.ChecksumSizeReceive} MaxPeerID={_currentVersion.MaxPeerID}");
        Log($"Auto-detect: {_autoDetect}");
        Log($"Game mode: {_config.GameMode}");
        Log($"Map: {_config.MapId}");
        Log($"Players: {_config.Players.Count}");
        Log($"");

        if (_autoDetect)
        {
            StartWithAutoDetect();
        }
        else
        {
            StartWithVersion(_currentVersion);
        }
    }

    /// <summary>
    /// Try each protocol version. Start with the most likely one for modern clients.
    /// Each version runs for a few seconds; if a client connects, we lock it in.
    /// If no client connects within the timeout, we try the next version.
    /// </summary>
    private void StartWithAutoDetect()
    {
        Log($"[AUTO-DETECT] Will try {VersionsToTry.Length} protocol versions (10s each)...");

        for (int attempt = 0; attempt < VersionsToTry.Length; attempt++)
        {
            var version = VersionsToTry[attempt];
            Log($"");
            Log($"[AUTO-DETECT] Attempt {attempt + 1}/{VersionsToTry.Length}: ChecksumSend={version.ChecksumSizeSend} ChecksumRecv={version.ChecksumSizeReceive}");

            try
            {
                _currentVersion = version;
                _versionIndex = attempt;

                var address = new Address(0u, (ushort)_port);
                _server = new Host(version, address, 32, 32, 0, 0, 996);
                _running = true;

                Log($"[OK] Listening on UDP port {_port} with this version...");

                // Try this version for 10 seconds
                var ev = new Event();
                var deadline = DateTime.Now.AddSeconds(10);

                while (DateTime.Now < deadline)
                {
                    int result = _server.HostService(ev, 500);

                    if (result > 0 && ev.Type == EventType.CONNECT)
                    {
                        HandleConnect(ev);
                        _connectionAttempts++;
                        _autoDetect = false;
                        Log($"[AUTO-DETECT] Client connected! Protocol version LOCKED.");
                        RunEventLoop(); // Continue with this version
                        return;
                    }

                    if (result > 0 && ev.Type == EventType.RECEIVE)
                    {
                        // Got data! This version might work
                        HandleReceive(ev);
                        _autoDetect = false;
                        Log($"[AUTO-DETECT] Received data! Protocol version LOCKED.");
                        RunEventLoop();
                        return;
                    }
                }

                Log($"[AUTO-DETECT] No connection on this version, trying next...");
                _server.Dispose();
                _server = null;
            }
            catch (Exception ex)
            {
                Log($"[AUTO-DETECT] Version failed: {ex.Message}");
                _server?.Dispose();
                _server = null;
            }
        }

        // All versions tried, restart with first version and wait indefinitely
        Log($"");
        Log($"[AUTO-DETECT] No client connected during auto-detect.");
        Log($"[AUTO-DETECT] Starting with Season8_Server (most likely for modern client) and waiting...");
        _currentVersion = VersionsToTry[0];
        _autoDetect = true;
        StartWithVersion(_currentVersion);
    }

    private void StartWithVersion(LENet.Version version)
    {
        var address = new Address(0u, (ushort)_port);

        try
        {
            _server = new Host(version, address, 32, 32, 0, 0, 996);
        }
        catch (Exception ex)
        {
            Log($"[ERROR] Failed to create LENet Host: {ex.Message}");
            throw;
        }

        _running = true;
        Log($"[OK] Server listening on UDP port {_port}");
        Log($"Waiting for client connection...");
        Log($"");

        RunEventLoop();
    }

    private void RunEventLoop()
    {
        var ev = new Event();
        int noActivityTicks = 0;
        const int maxNoActivityForAutoDetect = 300; // ~30 seconds

        while (_running && _server != null)
        {
            int result = _server.HostService(ev, 100);

            if (result < 0)
            {
                Log($"[ERROR] HostService returned error");
                if (_autoDetect && _connectionAttempts == 0)
                {
                    Log($"[AUTO-DETECT] ENet error, trying next version...");
                    break; // Try next version
                }
                continue;
            }

            if (result == 0)
            {
                // No activity — if auto-detecting and we've waited too long without
                // a connection, keep waiting (client might not be started yet)
                noActivityTicks++;
                continue;
            }

            noActivityTicks = 0;

            switch (ev.Type)
            {
                case EventType.CONNECT:
                    HandleConnect(ev);
                    _connectionAttempts++;
                    _lastConnectionTime = DateTime.Now;
                    if (_autoDetect)
                    {
                        _autoDetect = false; // Found working version
                        Log($"[AUTO-DETECT] Client connected! Protocol version locked.");
                    }
                    break;

                case EventType.RECEIVE:
                    HandleReceive(ev);
                    break;

                case EventType.DISCONNECT:
                    HandleDisconnect(ev);
                    break;

                case EventType.NONE:
                    break;
            }
        }
    }

    private void HandleConnect(Event ev)
    {
        var peer = ev.Peer;
        var peerId = peer.IncomingPeerID;

        Log($"[CONNECT] Client connected! PeerID={peerId}, Address={peer.Address.Host}:{peer.Address.Port}");

        var clientInfo = new ClientInfo
        {
            Peer = peer,
            ClientId = peerId,
            State = ClientState.Connected
        };

        // Assign blowfish key from config
        var playerConfig = GetPlayerConfig(peerId);
        var key = playerConfig?.BlowfishKey ?? _config.BlowfishKey;
        clientInfo.Cipher = BlowFish.FromBase64(key);

        _clients[peerId] = clientInfo;
        Log($"[CONNECT] Blowfish key assigned for client {peerId}");
    }

    private void HandleReceive(Event ev)
    {
        var peer = ev.Peer;
        var channel = ev.ChannelID;
        var packet = ev.Packet;

        var data = new byte[packet.DataLength];
        Array.Copy(packet.Data, data, packet.DataLength);

        var peerId = peer.IncomingPeerID;
        if (!_clients.TryGetValue(peerId, out var client))
        {
            Log($"[WARN] Received packet from unknown peer {peerId}");
            return;
        }

        // Raw capture mode - log everything
        if (_rawCaptureMode)
        {
            LogRawPacket(data, channel, client);
        }

        // Channel 0 (Handshake) is NEVER encrypted
        if (channel == (byte)Channel.Handshake)
        {
            HandleHandshakePacket(data, client);
            return;
        }

        // Decrypt the packet payload
        byte[] decrypted;
        try
        {
            decrypted = client.Cipher!.Decrypt(data);
        }
        catch (Exception ex)
        {
            Log($"[WARN] Failed to decrypt packet on channel {channel}: {ex.Message}");
            LogRawPacket(data, channel, client);
            return;
        }

        if (_rawCaptureMode)
        {
            Log($"  [DECRYPTED] Channel={channel} Len={decrypted.Length} First4={BitConverter.ToString(decrypted, 0, Math.Min(4, decrypted.Length))}");
        }

        // Route to packet handler
        _handler.HandlePacket(decrypted, (Channel)channel, client);
    }

    private void HandleHandshakePacket(byte[] data, ClientInfo client)
    {
        Log($"[HANDSHAKE] Received {data.Length} bytes from client {client.ClientId}");
        Log($"  Raw: {BitConverter.ToString(data, 0, Math.Min(32, data.Length))}");

        if (data.Length >= KeyCheck.PacketSize)
        {
            try
            {
                var keyCheck = KeyCheck.Deserialize(data);
                Log($"  {keyCheck}");

                if (client.Cipher != null)
                {
                    bool valid = keyCheck.Verify(client.Cipher);
                    Log($"  Checksum valid: {valid}");

                    // Check for reconnection
                    if (IsAwaitingReconnect(keyCheck.PlayerId))
                    {
                        var oldClient = TryReconnect(keyCheck.PlayerId, client);
                        if (oldClient != null)
                        {
                            Log($"  [RECONNECT] Reconnection successful!");
                        }
                    }
                    else
                    {
                        client.PlayerId = keyCheck.PlayerId;
                        client.State = ClientState.Authenticated;
                    }

                    // Send KeyCheck response
                    var response = KeyCheck.CreateResponse(
                        client.ClientId,
                        keyCheck.PlayerId,
                        client.Cipher
                    );

                    SendPacket(client, response.Serialize(), Channel.Handshake);
                    Log($"  [OK] KeyCheck response sent!");
                }
            }
            catch (Exception ex)
            {
                Log($"  [WARN] Failed to parse as KeyCheck: {ex.Message}");
                Log($"  This might be a different protocol version. Raw bytes logged above.");

                // In raw capture mode, save the failed packet for analysis
                if (_rawCaptureMode)
                    OnRawPacket?.Invoke(data, 0, "failed_keycheck");
            }
        }
        else
        {
            Log($"  [INFO] Packet too small for KeyCheck ({data.Length} < {KeyCheck.PacketSize})");
        }
    }

    // Disconnected players eligible for reconnection
    private readonly Dictionary<ulong, ClientInfo> _disconnectedPlayers = new();

    private void HandleDisconnect(Event ev)
    {
        var peerId = ev.Peer.IncomingPeerID;

        if (_clients.TryGetValue(peerId, out var client))
        {
            Log($"[DISCONNECT] Client {peerId} ({client.SummonerName ?? client.Name}) disconnected");
            client.State = ClientState.Disconnected;

            // Store for reconnection (keyed by PlayerId)
            if (client.PlayerId != 0)
            {
                _disconnectedPlayers[client.PlayerId] = client;
                Log($"  [RECONNECT] Player {client.PlayerId} saved for reconnection (champion: {client.Champion})");
            }

            _clients.Remove(peerId);
        }
        else
        {
            Log($"[DISCONNECT] Unknown client {peerId} disconnected");
        }
    }

    /// <summary>
    /// Try to reconnect a player using their PlayerId from the KeyCheck.
    /// </summary>
    public ClientInfo? TryReconnect(ulong playerId, ClientInfo newClient)
    {
        if (_disconnectedPlayers.TryGetValue(playerId, out var oldClient))
        {
            Log($"[RECONNECT] Player {playerId} ({oldClient.SummonerName}) is reconnecting!");

            newClient.SummonerName = oldClient.SummonerName;
            newClient.Champion = oldClient.Champion;
            newClient.SkinId = oldClient.SkinId;
            newClient.ChampionNetId = oldClient.ChampionNetId;
            newClient.Team = oldClient.Team;
            newClient.State = ClientState.InGame;

            _disconnectedPlayers.Remove(playerId);
            return oldClient;
        }
        return null;
    }

    public bool IsAwaitingReconnect(ulong playerId)
        => _disconnectedPlayers.ContainsKey(playerId);

    public void SendPacket(ClientInfo client, byte[] data, Channel channel)
    {
        byte[] toSend;
        if (channel != Channel.Handshake && client.Cipher != null)
        {
            toSend = client.Cipher.Encrypt(data);
        }
        else
        {
            toSend = data;
        }

        var packet = new Packet(toSend, PacketFlags.RELIABLE);
        client.Peer.Send((byte)channel, packet);
    }

    public void BroadcastPacket(byte[] data, Channel channel)
    {
        foreach (var client in _clients.Values)
        {
            if (client.State == ClientState.InGame || client.State == ClientState.Loading || client.State == ClientState.Authenticated)
                SendPacket(client, data, channel);
        }
    }

    public void BroadcastPacketToTeam(byte[] data, Channel channel, Config.TeamId team)
    {
        foreach (var client in _clients.Values)
        {
            if (client.Team == team && (client.State == ClientState.InGame || client.State == ClientState.Loading))
                SendPacket(client, data, channel);
        }
    }

    private void LogRawPacket(byte[] data, byte channel, ClientInfo client)
    {
        var hex = BitConverter.ToString(data, 0, Math.Min(64, data.Length));
        var truncated = data.Length > 64 ? "..." : "";
        Log($"  [RAW] Client={client.ClientId} Ch={channel} Len={data.Length} Data={hex}{truncated}");
        OnRawPacket?.Invoke(data, channel, $"Client {client.ClientId}");
    }

    private PlayerConfig? GetPlayerConfig(ushort clientId)
    {
        if (clientId < _config.Players.Count)
            return _config.Players[clientId];
        return null;
    }

    /// <summary>
    /// Fallback: raw UDP socket for when LENet version is incompatible.
    /// Captures raw ENet packets for protocol analysis.
    /// </summary>
    private void StartRawUdpFallback()
    {
        Log($"[FALLBACK] Starting raw UDP listener on port {_port}...");
        using var socket = new System.Net.Sockets.UdpClient(_port);
        _running = true;

        Log($"[OK] Raw UDP listener active. Waiting for packets...");
        Log($"[INFO] Raw packets will be saved to logs/packets/ for analysis");

        while (_running)
        {
            if (socket.Available > 0)
            {
                System.Net.IPEndPoint? remote = null;
                var data = socket.Receive(ref remote);
                Log($"[RAW-UDP] From={remote} Len={data.Length}");
                Log($"  Hex: {BitConverter.ToString(data, 0, Math.Min(128, data.Length))}");
                AnalyzeRawENetHeader(data);
                OnRawPacket?.Invoke(data, 255, $"raw_udp_{remote}");
            }
            else
            {
                Thread.Sleep(10);
            }
        }
    }

    private void AnalyzeRawENetHeader(byte[] data)
    {
        if (data.Length < 4) return;

        Log($"  [ANALYZE] Potential ENet header ({data.Length} bytes):");

        // Try Patch 4.20: [4B CRC32][1B sessionID][1B peerID|flags]
        if (data.Length >= 6)
        {
            var crc32 = BitConverter.ToUInt32(data, 0);
            Log($"    Patch420: CRC32={crc32:X8} Session=0x{data[4]:X2} PeerFlags=0x{data[5]:X2}");
        }

        // Try Season 8+: [8B checksum][1B sessionID][1B peerID|flags]
        if (data.Length >= 10)
        {
            var checksum64 = BitConverter.ToUInt64(data, 0);
            Log($"    Season8+: Checksum64={checksum64:X16} Session=0x{data[8]:X2} PeerFlags=0x{data[9]:X2}");
        }

        // Try no checksum: [1B sessionID][1B peerID|flags]
        Log($"    NoCheck: Session=0x{data[0]:X2} PeerFlags=0x{data[1]:X2}");

        // Detect ENet protocol command in first data byte (after checksum)
        foreach (var offset in new[] { 4, 8, 0 })
        {
            if (data.Length <= offset + 1) continue;
            var cmdByte = data[offset];
            var enetCmd = cmdByte & 0x0F;
            if (enetCmd >= 1 && enetCmd <= 12)
            {
                Log($"    @offset={offset}: ENet cmd={enetCmd} (0x{cmdByte:X2}) — possible protocol header size={offset}");
            }
        }
    }

    public void Stop()
    {
        _running = false;
        _server?.Dispose();
        _server = null;
        Log("[STOP] Server stopped");
    }

    public void TryNextVersion()
    {
        _versionIndex = (_versionIndex + 1) % VersionsToTry.Length;
        _currentVersion = VersionsToTry[_versionIndex];
        Log($"[VERSION] Switching to: ChecksumSend={_currentVersion.ChecksumSizeSend} ChecksumRecv={_currentVersion.ChecksumSizeReceive}");
    }

    private void Log(string message)
    {
        var timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
        var formatted = $"[{timestamp}] {message}";
        Console.WriteLine(formatted);
        OnLog?.Invoke(formatted);
    }

    public void Dispose()
    {
        Stop();
    }
}

public class ClientInfo
{
    public Peer Peer { get; set; } = null!;
    public ushort ClientId { get; set; }
    public ulong PlayerId { get; set; }
    public BlowFish? Cipher { get; set; }
    public ClientState State { get; set; }
    public string Name { get; set; } = "";
    public string? SummonerName { get; set; }
    public string Champion { get; set; } = "";
    public int SkinId { get; set; }
    public float LoadingProgress { get; set; }
    public uint ChampionNetId { get; set; }
    public Config.TeamId Team { get; set; }
}

public enum ClientState
{
    Connected,
    Authenticated,
    Loading,
    InGame,
    Disconnected
}
