using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using LoLServer.Core.Config;
using LoLServer.Core.Protocol;
using LoLServer.Core.Protocol.Packets;

namespace LoLServer.Core.Network;

/// <summary>
/// DTLS game server for modern LoL client (16.6+).
/// The client uses Encryption=true which enables DTLS at the transport level.
/// After DTLS handshake, plain ENet protocol runs inside.
/// </summary>
public class DtlsGameServer : IGameServer, IDisposable
{
    private UdpClient? _socket;
    private readonly int _port;
    private readonly GameConfig _config;
    private readonly PacketHandler _handler;
    private readonly Dictionary<ushort, ClientInfo> _clients = new();
    private readonly ConcurrentDictionary<string, DtlsPeer> _peers = new();
    private readonly ConcurrentDictionary<string, ConcurrentQueue<byte[]>> _queues = new();
    private bool _running;
    private ushort _nextPeerId;
    private readonly Org.BouncyCastle.Tls.Crypto.Impl.BC.BcTlsCrypto _crypto;

    public event Action<string>? OnLog;
    public IReadOnlyDictionary<ushort, ClientInfo> Clients => _clients;

    public DtlsGameServer(int port, GameConfig config)
    {
        _port = port;
        _config = config;
        _handler = new PacketHandler(config, this);
        _crypto = new Org.BouncyCastle.Tls.Crypto.Impl.BC.BcTlsCrypto(new SecureRandom());
    }

    public void Start()
    {
        Log("=== LoL Private Server (DTLS Mode) ===");
        Log($"Port: {_port}");
        Log($"Players: {_config.Players.Count}");
        Log("");

        _socket = new UdpClient(_port);
        _running = true;

        Log($"[OK] Listening on UDP port {_port} (DTLS)");
        Log("Waiting for LoL client...");
        Log("");

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

            var key = remote!.ToString();
            var queue = _queues.GetOrAdd(key, _ => new ConcurrentQueue<byte[]>());

            // Try both: raw data and data with 8-byte header stripped
            queue.Enqueue(data);

            if (!_peers.ContainsKey(key))
            {
                var peer = new DtlsPeer
                {
                    Remote = remote,
                    PeerId = _nextPeerId++,
                    Key = key,
                };
                _peers[key] = peer;

                Log($"[NEW] {key} → PeerId={peer.PeerId}, {data.Length}B");
                Log($"  First16: {BitConverter.ToString(data, 0, Math.Min(16, data.Length))}");

                // Detect if 8-byte header needs stripping
                bool hasRiotHeader = data.Length > 13 && data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 0;
                if (hasRiotHeader)
                {
                    // Check if DTLS record starts at offset 8
                    byte ct = data[8];
                    if (ct >= 20 && ct <= 25)
                    {
                        peer.HeaderOffset = 8;
                        Log($"  DTLS at offset 8 (content_type=0x{ct:X2})");
                    }
                    else
                    {
                        Log($"  No DTLS at offset 8 (byte=0x{ct:X2}), trying raw...");
                        // Try both offsets
                        peer.HeaderOffset = 0;
                    }
                }

                // Start DTLS handshake thread
                var t = new Thread(() => DtlsHandshake(peer)) { IsBackground = true, Name = $"DTLS-{key}" };
                t.Start();

                // Also try with headerOffset=8 in parallel if we're unsure
                if (hasRiotHeader && peer.HeaderOffset == 0)
                {
                    var peer2key = key + ":h8";
                    var peer2 = new DtlsPeer { Remote = remote, PeerId = peer.PeerId, Key = key, HeaderOffset = 8 };
                    // Re-enqueue the data for the second attempt
                    var q2 = _queues.GetOrAdd(peer2key, _ => new ConcurrentQueue<byte[]>());
                    q2.Enqueue(data);
                    var t2 = new Thread(() => DtlsHandshakeAlt(peer2, peer2key)) { IsBackground = true, Name = $"DTLS-h8-{key}" };
                    t2.Start();
                }
            }
        }
    }

    private void DtlsHandshake(DtlsPeer peer)
    {
        try
        {
            Log($"[DTLS] Handshake with {peer.Key} (offset={peer.HeaderOffset})...");
            var transport = new UdpQueueTransport(_socket!, peer.Remote, peer.Key, _queues, peer.HeaderOffset, Log);
            var protocol = new DtlsServerProtocol();
            var server = new LoLTlsServer(_crypto, Log);

            var dtls = protocol.Accept(server, transport);
            Log($"[DTLS] === HANDSHAKE SUCCESS! === {peer.Key}");
            peer.Transport = dtls;
            peer.Connected = true;

            var client = EnsureClient(peer);
            ReadLoop(peer, client, dtls);
        }
        catch (Exception ex)
        {
            Log($"[DTLS] Handshake failed ({peer.Key}): {ex.GetType().Name}: {ex.Message}");
        }
        finally
        {
            peer.Connected = false;
            _peers.TryRemove(peer.Key, out _);
        }
    }

    private void DtlsHandshakeAlt(DtlsPeer peer, string queueKey)
    {
        try
        {
            Log($"[DTLS-ALT] Handshake with header offset 8...");
            var transport = new UdpQueueTransport(_socket!, peer.Remote, queueKey, _queues, 8, Log);
            var protocol = new DtlsServerProtocol();
            var server = new LoLTlsServer(_crypto, Log);

            var dtls = protocol.Accept(server, transport);
            Log($"[DTLS-ALT] === HANDSHAKE SUCCESS (offset=8)! ===");
            peer.Transport = dtls;
            peer.HeaderOffset = 8;
            peer.Connected = true;

            var client = EnsureClient(peer);
            ReadLoop(peer, client, dtls);
        }
        catch (Exception ex)
        {
            Log($"[DTLS-ALT] Failed: {ex.GetType().Name}: {ex.Message}");
        }
        finally
        {
            _queues.TryRemove(queueKey, out _);
        }
    }

    private void ReadLoop(DtlsPeer peer, ClientInfo client, DtlsTransport dtls)
    {
        var buf = new byte[4096];
        while (_running && peer.Connected)
        {
            try
            {
                int len = dtls.Receive(buf, 0, buf.Length, 2000);
                if (len > 0)
                {
                    var enet = new byte[len];
                    Array.Copy(buf, enet, len);
                    ProcessENet(enet, peer, client);
                }
            }
            catch (TlsTimeoutException) { }
            catch (Exception ex)
            {
                Log($"[DTLS] Read error: {ex.Message}");
                break;
            }
        }
    }

    private void ProcessENet(byte[] data, DtlsPeer peer, ClientInfo client)
    {
        Log($"[ENet] {data.Length}B: {BitConverter.ToString(data, 0, Math.Min(16, data.Length))}");

        for (int cs = 8; cs >= 0; cs -= 4)
        {
            if (cs + 5 > data.Length) continue;
            byte cmd = (byte)(data[cs + 4] & 0x0F);
            if (cmd < 1 || cmd > 12) continue;

            ushort pid = (ushort)(data[cs] | (data[cs + 1] << 8));
            Log($"  ENet@{cs}: PeerID=0x{pid:X4} Cmd={cmd}");

            switch (cmd)
            {
                case 2: // CONNECT
                    Log($"  CONNECT!");
                    SendVerify(peer);
                    return;
                case 6: // RELIABLE
                    if (cs + 6 <= data.Length)
                    {
                        byte ch = data[cs + 5];
                        ushort seq = BitConverter.ToUInt16(data, cs + 6);
                        ushort dLen = (cs + 8 < data.Length) ? BitConverter.ToUInt16(data, cs + 8) : (ushort)0;
                        Log($"  RELIABLE ch={ch} seq={seq} len={dLen}");
                        if (ch == 0 && cs + 10 + dLen <= data.Length)
                        {
                            var payload = new byte[dLen];
                            Array.Copy(data, cs + 10, payload, 0, dLen);
                            HandleHandshake(payload, peer, client);
                        }
                    }
                    return;
                case 1: return; // ACK
                case 5: return; // PING
                case 4: peer.Connected = false; return; // DISCONNECT
            }
        }
    }

    private void HandleHandshake(byte[] data, DtlsPeer peer, ClientInfo client)
    {
        if (data.Length >= KeyCheck.PacketSize)
        {
            try
            {
                var kc = KeyCheck.Deserialize(data);
                Log($"  KEYCHECK: {kc}");
                client.PlayerId = kc.PlayerId;
                client.State = ClientState.Authenticated;
                var resp = KeyCheck.CreateResponse(client.ClientId, kc.PlayerId, client.Cipher!);
                SendReliable(peer, 0, resp.Serialize());
                Log($"  KeyCheck response sent!");
            }
            catch (Exception ex) { Log($"  KeyCheck failed: {ex.Message}"); }
        }
    }

    private void SendVerify(DtlsPeer peer)
    {
        var d = new byte[40];
        int o = 8;
        d[o] = 0xFF; d[o + 1] = 0xFF;
        ushort t = (ushort)(Environment.TickCount & 0xFFFF);
        d[o + 2] = (byte)(t & 0xFF); d[o + 3] = (byte)(t >> 8);
        o += 4;
        d[o] = 0x83; d[o + 1] = 0xFF; d[o + 2] = 1;
        d[o + 4] = (byte)(peer.PeerId & 0xFF); d[o + 5] = (byte)(peer.PeerId >> 8);
        BitConverter.GetBytes(996u).CopyTo(d, o + 8);
        BitConverter.GetBytes(32768u).CopyTo(d, o + 12);
        BitConverter.GetBytes(32u).CopyTo(d, o + 16);
        SendDtls(peer, d);
    }

    private void SendReliable(DtlsPeer peer, byte ch, byte[] payload)
    {
        var d = new byte[8 + 4 + 6 + payload.Length];
        int o = 8;
        d[o] = 0xFF; d[o + 1] = 0xFF;
        ushort t = (ushort)(Environment.TickCount & 0xFFFF);
        d[o + 2] = (byte)(t & 0xFF); d[o + 3] = (byte)(t >> 8);
        o += 4;
        d[o] = 0x86; d[o + 1] = ch; d[o + 2] = 1;
        BitConverter.GetBytes((ushort)payload.Length).CopyTo(d, o + 4);
        Array.Copy(payload, 0, d, o + 6, payload.Length);
        SendDtls(peer, d);
    }

    private void SendDtls(DtlsPeer peer, byte[] data)
    {
        try { peer.Transport?.Send(data, 0, data.Length); }
        catch (Exception ex) { Log($"[DTLS] Send: {ex.Message}"); }
    }

    private ClientInfo EnsureClient(DtlsPeer peer)
    {
        if (!_clients.TryGetValue(peer.PeerId, out var c))
        {
            c = new ClientInfo { Peer = null!, ClientId = peer.PeerId, State = ClientState.Connected };
            var pc = peer.PeerId < _config.Players.Count ? _config.Players[peer.PeerId] : _config.Players[0];
            c.Cipher = BlowFish.FromBase64(pc.BlowfishKey ?? _config.BlowfishKey);
            _clients[peer.PeerId] = c;
        }
        return c;
    }

    public void SendPacket(ClientInfo client, byte[] data, Channel channel)
    {
        foreach (var p in _peers.Values)
            if (p.PeerId == client.ClientId && p.Transport != null)
            {
                byte[] enc = (channel != Channel.Handshake && client.Cipher != null) ? client.Cipher.Encrypt(data) : data;
                SendReliable(p, (byte)channel, enc);
                break;
            }
    }

    public void BroadcastPacket(byte[] data, Channel channel)
    {
        foreach (var c in _clients.Values)
            if (c.State >= ClientState.Authenticated) SendPacket(c, data, channel);
    }

    public void BroadcastPacketToTeam(byte[] data, Channel channel, TeamId team)
    {
        foreach (var c in _clients.Values)
            if (c.Team == team && c.State >= ClientState.InGame) SendPacket(c, data, channel);
    }

    public void Stop() { _running = false; _socket?.Close(); }
    public void Dispose() => Stop();

    private void Log(string msg)
    {
        var s = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        Console.WriteLine(s);
        OnLog?.Invoke(s);
    }

    private class DtlsPeer
    {
        public IPEndPoint Remote { get; set; } = null!;
        public string Key { get; set; } = "";
        public ushort PeerId { get; set; }
        public int HeaderOffset { get; set; }
        public bool Connected { get; set; }
        public DtlsTransport? Transport { get; set; }
    }
}

/// <summary>
/// UDP transport backed by a concurrent queue (fed by the main receive loop).
/// </summary>
internal class UdpQueueTransport : DatagramTransport
{
    private readonly UdpClient _socket;
    private readonly IPEndPoint _remote;
    private readonly string _queueKey;
    private readonly ConcurrentDictionary<string, ConcurrentQueue<byte[]>> _queues;
    private readonly int _headerOffset;
    private readonly Action<string>? _log;

    public UdpQueueTransport(UdpClient socket, IPEndPoint remote, string queueKey,
        ConcurrentDictionary<string, ConcurrentQueue<byte[]>> queues, int headerOffset, Action<string>? log)
    {
        _socket = socket;
        _remote = remote;
        _queueKey = queueKey;
        _queues = queues;
        _headerOffset = headerOffset;
        _log = log;
    }

    public int GetReceiveLimit() => 1500;
    public int GetSendLimit() => 1500;

    public int Receive(byte[] buf, int off, int len, int waitMillis)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(waitMillis);
        while (DateTime.UtcNow < deadline)
        {
            if (_queues.TryGetValue(_queueKey, out var q) && q.TryDequeue(out var data))
            {
                int start = _headerOffset;
                int n = Math.Min(data.Length - start, len);
                if (n <= 0) continue;
                Array.Copy(data, start, buf, off, n);
                return n;
            }
            Thread.Sleep(5);
        }
        return -1; // timeout
    }

    public int Receive(Span<byte> buffer, int waitMillis)
    {
        var buf = new byte[buffer.Length];
        int n = Receive(buf, 0, buf.Length, waitMillis);
        if (n > 0) buf.AsSpan(0, n).CopyTo(buffer);
        return n;
    }

    public void Send(byte[] buf, int off, int len)
    {
        byte[] packet;
        if (_headerOffset > 0)
        {
            packet = new byte[_headerOffset + len];
            Array.Copy(buf, off, packet, _headerOffset, len);
        }
        else
        {
            packet = new byte[len];
            Array.Copy(buf, off, packet, 0, len);
        }
        _socket.Send(packet, packet.Length, _remote);
    }

    public void Send(ReadOnlySpan<byte> buffer)
    {
        var buf = buffer.ToArray();
        Send(buf, 0, buf.Length);
    }

    public void Close() { }
}

/// <summary>
/// BouncyCastle DTLS server for the LoL client.
/// </summary>
internal class LoLTlsServer : DefaultTlsServer
{
    private readonly Action<string>? _log;

    public LoLTlsServer(Org.BouncyCastle.Tls.Crypto.Impl.BC.BcTlsCrypto crypto, Action<string>? log) : base(crypto)
    {
        _log = log;
    }

    protected override ProtocolVersion[] GetSupportedVersions()
    {
        return ProtocolVersion.DTLSv12.Only();
    }

    protected override int[] GetSupportedCipherSuites()
    {
        return new[]
        {
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
        };
    }

    public override TlsCredentials GetCredentials()
    {
        var crypto = (Org.BouncyCastle.Tls.Crypto.Impl.BC.BcTlsCrypto)m_context.Crypto;
        var random = crypto.SecureRandom;

        // Generate RSA key pair
        var keyGen = new RsaKeyPairGenerator();
        keyGen.Init(new KeyGenerationParameters(random, 2048));
        var keyPair = keyGen.GenerateKeyPair();

        // Generate self-signed X.509 certificate
        var certGen = new X509V3CertificateGenerator();
        certGen.SetSerialNumber(BigInteger.ProbablePrime(120, new SecureRandom()));
        certGen.SetIssuerDN(new X509Name("CN=localhost"));
        certGen.SetSubjectDN(new X509Name("CN=localhost"));
        certGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        certGen.SetNotAfter(DateTime.UtcNow.AddYears(5));
        certGen.SetPublicKey(keyPair.Public);
        var sigFactory = new Asn1SignatureFactory("SHA256WithRSA", keyPair.Private, random);
        var x509 = certGen.Generate(sigFactory);

        // Create TLS certificate
        var bcCert = new Org.BouncyCastle.Tls.Crypto.Impl.BC.BcTlsCertificate(crypto, x509.GetEncoded());
        var certChain = new Certificate(new TlsCertificate[] { bcCert });

        // Create signing credentials
        var sigCreds = new Org.BouncyCastle.Tls.Crypto.Impl.BC.BcDefaultTlsCredentialedSigner(
            new TlsCryptoParameters(m_context),
            crypto,
            keyPair.Private,
            certChain,
            SignatureAndHashAlgorithm.GetInstance(HashAlgorithm.sha256, SignatureAlgorithm.rsa));

        _log?.Invoke("[DTLS] Server credentials created");
        return sigCreds;
    }

    public override void NotifyAlertRaised(short alertLevel, short alertDescription, string message, Exception cause)
    {
        _log?.Invoke($"[DTLS] Alert: level={alertLevel} desc={alertDescription} msg={message}");
    }

    public override void NotifyHandshakeComplete()
    {
        _log?.Invoke("[DTLS] Handshake complete callback");
    }
}
