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
/// Supports multiple protocol versions for testing against modern client.
/// </summary>
public class PacketServer : IDisposable
{
    private Host? _server;
    private readonly int _port;
    private readonly GameConfig _config;
    private readonly PacketHandler _handler;
    private readonly Dictionary<ushort, ClientInfo> _clients = new();
    private bool _running;
    private bool _rawCaptureMode;

    // Protocol versions to try (note: LENet has typo "Seasson")
    private static readonly LENet.Version[] VersionsToTry =
    {
        LENet.Version.Patch420,          // 4-byte CRC32 both ways
        LENet.Version.Seasson8_Server,   // Server: 0 send, 8 receive checksum
        LENet.Version.Seasson8_Client,   // Client: 8 send, 0 receive checksum
        LENet.Version.Seasson12,         // Newer
        LENet.Version.Seasson34,         // Even newer
    };

    private int _versionIndex;
    private LENet.Version _currentVersion;

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

    public void Start()
    {
        Log($"=== LoL Private Server ===");
        Log($"Port: {_port}");
        Log($"Protocol: ChecksumSend={_currentVersion.ChecksumSizeSend} ChecksumRecv={_currentVersion.ChecksumSizeReceive} MaxPeerID={_currentVersion.MaxPeerID}");
        Log($"Game mode: {_config.GameMode}");
        Log($"Map: {_config.MapId}");
        Log($"Players: {_config.Players.Count}");
        Log($"");

        var address = new Address(0u, (ushort)_port); // 0 = INADDR_ANY

        try
        {
            _server = new Host(_currentVersion, address, 32, 32, 0, 0, 996);
        }
        catch (Exception ex)
        {
            Log($"[ERROR] Failed to create LENet Host: {ex.Message}");
            Log($"Falling back to raw UDP socket for protocol analysis...");
            StartRawUdpFallback();
            return;
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

        while (_running && _server != null)
        {
            int result = _server.HostService(ev, 100);

            if (result < 0)
            {
                Log($"[ERROR] HostService returned error");
                continue;
            }

            if (result == 0)
                continue;

            switch (ev.Type)
            {
                case EventType.CONNECT:
                    HandleConnect(ev);
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

                    // Accept anyway for testing (valid || true)
                    client.PlayerId = keyCheck.PlayerId;
                    client.State = ClientState.Authenticated;

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
            }
        }
        else
        {
            Log($"  [INFO] Packet too small for KeyCheck ({data.Length} < {KeyCheck.PacketSize})");
        }
    }

    private void HandleDisconnect(Event ev)
    {
        var peerId = ev.Peer.IncomingPeerID;
        Log($"[DISCONNECT] Client {peerId} disconnected");
        _clients.Remove(peerId);
    }

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
    /// </summary>
    private void StartRawUdpFallback()
    {
        Log($"[FALLBACK] Starting raw UDP listener on port {_port}...");
        using var socket = new System.Net.Sockets.UdpClient(_port);
        _running = true;

        Log($"[OK] Raw UDP listener active. Waiting for packets...");

        while (_running)
        {
            if (socket.Available > 0)
            {
                System.Net.IPEndPoint? remote = null;
                var data = socket.Receive(ref remote);
                Log($"[RAW-UDP] From={remote} Len={data.Length}");
                Log($"  Hex: {BitConverter.ToString(data, 0, Math.Min(128, data.Length))}");
                AnalyzeRawENetHeader(data);
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
    public string Champion { get; set; } = "";
    public int SkinId { get; set; }
    public float LoadingProgress { get; set; }
}

public enum ClientState
{
    Connected,
    Authenticated,
    Loading,
    InGame,
    Disconnected
}
