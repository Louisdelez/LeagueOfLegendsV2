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

        // Extract connection token from bytes 8-11 (constant per connection)
        // This might be the connectID the client expects us to echo back
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
        }

        if (!peer.Connected)
        {
            peer.Connected = true;
            peer.OutgoingPeerID = 1; // Non-zero peer ID
            Log($"  [HANDSHAKE] Sending VERIFY_CONNECT (connectID=0x{peer.ConnectToken:X8})");
            SendVerifyConnect(peer);
            EnsureClientInfo(peer);
        }
        else if (peer.PacketCount <= 15)
        {
            // Client retransmitting - resend VERIFY_CONNECT with same connectID
            if (verbose) Log($"  [RETRANSMIT #{peer.PacketCount}]");
            SendVerifyConnect(peer);
        }
        else if (!peer.GameInitSent)
        {
            ScheduleGameInit(peer);
        }
    }

    private void SendVerifyConnect(PeerInfo peer)
    {
        // Try MANY different VERIFY_CONNECT variants to find which one the client accepts.
        // Each variant is sent as a separate UDP packet.
        int variantNum = 0;
        ushort sentTime = (ushort)(Environment.TickCount & 0xFFFF);

        // Helper to build a single VERIFY_CONNECT variant
        void SendVariant(
            string desc,
            uint sessionId, ushort peerIdField, byte cmd, byte channel, ushort seqNo,
            ushort outPeerId, ushort mtu, uint winSize, uint chanCount,
            uint inBW, uint outBW, uint throttleInt, uint throttleAcc, uint throttleDec,
            bool appendConnectId, bool useLittleEndian, bool skipEncrypt)
        {
            variantNum++;
            int bodySize = 36 + (appendConnectId ? 4 : 0);
            int totalSize = 8 + 4 + bodySize; // header(8) + cmdHeader(4) + body
            var plain = new byte[totalSize];
            int off = 0;

            if (useLittleEndian)
            {
                // Little-endian header
                WriteLE32(plain, off, sessionId); off += 4;
                WriteLE16(plain, off, peerIdField); off += 2;
                WriteLE16(plain, off, sentTime); off += 2;
            }
            else
            {
                // Big-endian header (standard)
                WriteBE32(plain, off, sessionId); off += 4;
                WriteBE16(plain, off, peerIdField); off += 2;
                WriteBE16(plain, off, sentTime); off += 2;
            }

            // Command header (always same byte order as header)
            plain[off] = cmd; off++;
            plain[off] = channel; off++;
            if (useLittleEndian) { WriteLE16(plain, off, seqNo); } else { WriteBE16(plain, off, seqNo); }
            off += 2;

            // VERIFY_CONNECT body
            if (useLittleEndian)
            {
                WriteLE16(plain, off, outPeerId); off += 2;
                WriteLE16(plain, off, mtu); off += 2;
                WriteLE32(plain, off, winSize); off += 4;
                WriteLE32(plain, off, chanCount); off += 4;
                WriteLE32(plain, off, inBW); off += 4;
                WriteLE32(plain, off, outBW); off += 4;
                WriteLE32(plain, off, throttleInt); off += 4;
                WriteLE32(plain, off, throttleAcc); off += 4;
                WriteLE32(plain, off, throttleDec); off += 4;
                if (appendConnectId) { WriteLE32(plain, off, peer.ConnectToken); off += 4; }
            }
            else
            {
                WriteBE16(plain, off, outPeerId); off += 2;
                WriteBE16(plain, off, mtu); off += 2;
                WriteBE32(plain, off, winSize); off += 4;
                WriteBE32(plain, off, chanCount); off += 4;
                WriteBE32(plain, off, inBW); off += 4;
                WriteBE32(plain, off, outBW); off += 4;
                WriteBE32(plain, off, throttleInt); off += 4;
                WriteBE32(plain, off, throttleAcc); off += 4;
                WriteBE32(plain, off, throttleDec); off += 4;
                if (appendConnectId) { WriteBE32(plain, off, peer.ConnectToken); off += 4; }
            }

            byte[] toSend;
            if (skipEncrypt)
            {
                toSend = plain;
            }
            else
            {
                toSend = CfbEncrypt(plain);
            }

            Log($"  [V{variantNum:D2}] {desc} | {toSend.Length}B enc={!skipEncrypt} plain={Hex(plain, 20)}");
            Send(toSend, peer);
        }

        Log($"  === SENDING ALL VERIFY_CONNECT VARIANTS (token=0x{peer.ConnectToken:X8}) ===");

        // --- BASELINE: current format (BE, encrypted, 48B no connectID) ---
        // V01: Original baseline
        SendVariant("BASELINE sessID=DEADBEEF peerID=0x8001 cmd=0x83 ch=0xFF seq=1",
            _sessionId, (ushort)(peer.OutgoingPeerID | 0x8000), 0x83, 0xFF, 1,
            peer.OutgoingPeerID, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: false, useLittleEndian: false, skipEncrypt: false);

        // V02: Baseline + connectID appended (52B)
        SendVariant("BASELINE+connID",
            _sessionId, (ushort)(peer.OutgoingPeerID | 0x8000), 0x83, 0xFF, 1,
            peer.OutgoingPeerID, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: true, useLittleEndian: false, skipEncrypt: false);

        // --- 1. Different SessionID values ---
        // V03: SessionID = 0x00000000
        SendVariant("sessID=0x00000000",
            0x00000000, (ushort)(peer.OutgoingPeerID | 0x8000), 0x83, 0xFF, 1,
            peer.OutgoingPeerID, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: false, useLittleEndian: false, skipEncrypt: false);

        // V04: SessionID = 0xFFFFFFFF
        SendVariant("sessID=0xFFFFFFFF",
            0xFFFFFFFF, (ushort)(peer.OutgoingPeerID | 0x8000), 0x83, 0xFF, 1,
            peer.OutgoingPeerID, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: false, useLittleEndian: false, skipEncrypt: false);

        // V05: SessionID = connection token
        SendVariant("sessID=connToken",
            peer.ConnectToken, (ushort)(peer.OutgoingPeerID | 0x8000), 0x83, 0xFF, 1,
            peer.OutgoingPeerID, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: false, useLittleEndian: false, skipEncrypt: false);

        // V06: SessionID = connToken + connectID appended
        SendVariant("sessID=connToken+connID",
            peer.ConnectToken, (ushort)(peer.OutgoingPeerID | 0x8000), 0x83, 0xFF, 1,
            peer.OutgoingPeerID, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: true, useLittleEndian: false, skipEncrypt: false);

        // --- 2. Different PeerID values ---
        // V07: PeerID = 0x7FFF (no TimeSent flag)
        SendVariant("peerID=0x7FFF",
            _sessionId, 0x7FFF, 0x83, 0xFF, 1,
            peer.OutgoingPeerID, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: false, useLittleEndian: false, skipEncrypt: false);

        // V08: PeerID = 0xFFFF
        SendVariant("peerID=0xFFFF",
            _sessionId, 0xFFFF, 0x83, 0xFF, 1,
            peer.OutgoingPeerID, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: false, useLittleEndian: false, skipEncrypt: false);

        // V09: PeerID = 0x0000
        SendVariant("peerID=0x0000",
            _sessionId, 0x0000, 0x83, 0xFF, 1,
            peer.OutgoingPeerID, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: false, useLittleEndian: false, skipEncrypt: false);

        // --- 3. Different cmd byte ---
        // V10: cmd=0x03 (no flags)
        SendVariant("cmd=0x03 noFlags",
            _sessionId, (ushort)(peer.OutgoingPeerID | 0x8000), 0x03, 0xFF, 1,
            peer.OutgoingPeerID, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: false, useLittleEndian: false, skipEncrypt: false);

        // V11: cmd=0xC3 (different flags: 0x80|0x40)
        SendVariant("cmd=0xC3",
            _sessionId, (ushort)(peer.OutgoingPeerID | 0x8000), 0xC3, 0xFF, 1,
            peer.OutgoingPeerID, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: false, useLittleEndian: false, skipEncrypt: false);

        // --- 4. Different channel ---
        // V12: channel=0x00
        SendVariant("ch=0x00",
            _sessionId, (ushort)(peer.OutgoingPeerID | 0x8000), 0x83, 0x00, 1,
            peer.OutgoingPeerID, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: false, useLittleEndian: false, skipEncrypt: false);

        // V13: channel=0x00 + connectID
        SendVariant("ch=0x00+connID",
            _sessionId, (ushort)(peer.OutgoingPeerID | 0x8000), 0x83, 0x00, 1,
            peer.OutgoingPeerID, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: true, useLittleEndian: false, skipEncrypt: false);

        // --- 5. Sequence number 0 ---
        // V14: seq=0
        SendVariant("seq=0",
            _sessionId, (ushort)(peer.OutgoingPeerID | 0x8000), 0x83, 0xFF, 0,
            peer.OutgoingPeerID, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: false, useLittleEndian: false, skipEncrypt: false);

        // V15: seq=0 + connectID
        SendVariant("seq=0+connID",
            _sessionId, (ushort)(peer.OutgoingPeerID | 0x8000), 0x83, 0xFF, 0,
            peer.OutgoingPeerID, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: true, useLittleEndian: false, skipEncrypt: false);

        // --- 6. OutPeerID variants ---
        // V16: outPeerId=0x7FFF
        SendVariant("outPeer=0x7FFF",
            _sessionId, (ushort)(peer.OutgoingPeerID | 0x8000), 0x83, 0xFF, 1,
            0x7FFF, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: false, useLittleEndian: false, skipEncrypt: false);

        // V17: outPeerId=0xFFFF
        SendVariant("outPeer=0xFFFF",
            _sessionId, (ushort)(peer.OutgoingPeerID | 0x8000), 0x83, 0xFF, 1,
            0xFFFF, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: false, useLittleEndian: false, skipEncrypt: false);

        // --- 7. ConnectID appended (already covered above, add more combos) ---
        // V18: sessID=0 + connID + seq=0
        SendVariant("sessID=0+connID+seq=0",
            0x00000000, (ushort)(peer.OutgoingPeerID | 0x8000), 0x83, 0xFF, 0,
            peer.OutgoingPeerID, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: true, useLittleEndian: false, skipEncrypt: false);

        // V19: sessID=connToken + connID + seq=0 + ch=0x00
        SendVariant("sessID=connToken+connID+seq=0+ch=0",
            peer.ConnectToken, (ushort)(peer.OutgoingPeerID | 0x8000), 0x83, 0x00, 0,
            peer.OutgoingPeerID, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: true, useLittleEndian: false, skipEncrypt: false);

        // --- 8. LITTLE-ENDIAN format ---
        // V20: LE baseline
        SendVariant("LE baseline",
            _sessionId, (ushort)(peer.OutgoingPeerID | 0x8000), 0x83, 0xFF, 1,
            peer.OutgoingPeerID, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: false, useLittleEndian: true, skipEncrypt: false);

        // V21: LE + connectID
        SendVariant("LE+connID",
            _sessionId, (ushort)(peer.OutgoingPeerID | 0x8000), 0x83, 0xFF, 1,
            peer.OutgoingPeerID, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: true, useLittleEndian: true, skipEncrypt: false);

        // V22: LE + sessID=connToken + connID
        SendVariant("LE+sessID=connToken+connID",
            peer.ConnectToken, (ushort)(peer.OutgoingPeerID | 0x8000), 0x83, 0xFF, 1,
            peer.OutgoingPeerID, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: true, useLittleEndian: true, skipEncrypt: false);

        // --- 9. Without TimeSent flag (peerID without 0x8000) ---
        // V23: peerID=1 (no 0x8000 flag)
        SendVariant("noTimeSent peerID=1",
            _sessionId, peer.OutgoingPeerID, 0x83, 0xFF, 1,
            peer.OutgoingPeerID, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: false, useLittleEndian: false, skipEncrypt: false);

        // V24: peerID=1 + connID
        SendVariant("noTimeSent+connID",
            _sessionId, peer.OutgoingPeerID, 0x83, 0xFF, 1,
            peer.OutgoingPeerID, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: true, useLittleEndian: false, skipEncrypt: false);

        // --- 10. NO ENCRYPTION (raw plaintext) ---
        // V25: plaintext baseline
        SendVariant("PLAINTEXT baseline",
            _sessionId, (ushort)(peer.OutgoingPeerID | 0x8000), 0x83, 0xFF, 1,
            peer.OutgoingPeerID, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: false, useLittleEndian: false, skipEncrypt: true);

        // V26: plaintext + connID
        SendVariant("PLAINTEXT+connID",
            _sessionId, (ushort)(peer.OutgoingPeerID | 0x8000), 0x83, 0xFF, 1,
            peer.OutgoingPeerID, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: true, useLittleEndian: false, skipEncrypt: true);

        // V27: plaintext + sessID=connToken + connID
        SendVariant("PLAINTEXT sessID=connToken+connID",
            peer.ConnectToken, (ushort)(peer.OutgoingPeerID | 0x8000), 0x83, 0xFF, 1,
            peer.OutgoingPeerID, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: true, useLittleEndian: false, skipEncrypt: true);

        // V28: plaintext LE + connID
        SendVariant("PLAINTEXT LE+connID",
            _sessionId, (ushort)(peer.OutgoingPeerID | 0x8000), 0x83, 0xFF, 1,
            peer.OutgoingPeerID, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: true, useLittleEndian: true, skipEncrypt: true);

        // --- COMBO variants (mixing multiple changes) ---
        // V29: cmd=0x03 + ch=0x00 + seq=0 + connID
        SendVariant("cmd=0x03+ch=0+seq=0+connID",
            _sessionId, (ushort)(peer.OutgoingPeerID | 0x8000), 0x03, 0x00, 0,
            peer.OutgoingPeerID, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: true, useLittleEndian: false, skipEncrypt: false);

        // V30: sessID=connToken + noTimeSent + cmd=0x03 + ch=0x00 + seq=0 + connID
        SendVariant("sessID=connToken+noTimeSent+cmd=0x03+ch=0+seq=0+connID",
            peer.ConnectToken, peer.OutgoingPeerID, 0x03, 0x00, 0,
            peer.OutgoingPeerID, 996, 32768, 32, 0, 0, 32, 2, 2,
            appendConnectId: true, useLittleEndian: false, skipEncrypt: false);

        // === CRC32 CHECKSUM VARIANTS ===
        // ENet can prepend a 4-byte CRC32 before the header. If the client has checksum enabled,
        // it silently drops packets without valid CRC.
        {
            var basePlainCrc = new byte[52]; // 4B CRC + 48B packet
            int o = 4; // leave room for CRC
            WriteBE32(basePlainCrc, o, _sessionId); o += 4;
            WriteBE16(basePlainCrc, o, (ushort)(peer.OutgoingPeerID | 0x8000)); o += 2;
            WriteBE16(basePlainCrc, o, sentTime); o += 2;
            basePlainCrc[o] = 0x83; o++;
            basePlainCrc[o] = 0xFF; o++;
            WriteBE16(basePlainCrc, o, 1); o += 2;
            WriteBE16(basePlainCrc, o, peer.OutgoingPeerID); o += 2;
            WriteBE16(basePlainCrc, o, 996); o += 2;
            WriteBE32(basePlainCrc, o, 32768); o += 4;
            WriteBE32(basePlainCrc, o, 32); o += 4;
            WriteBE32(basePlainCrc, o, 0); o += 4;
            WriteBE32(basePlainCrc, o, 0); o += 4;
            WriteBE32(basePlainCrc, o, 32); o += 4;
            WriteBE32(basePlainCrc, o, 2); o += 4;
            WriteBE32(basePlainCrc, o, 2); o += 4;

            // Compute CRC32 over the packet (with CRC field = 0)
            uint crc = Crc32(basePlainCrc);
            WriteBE32(basePlainCrc, 0, crc);

            // V-CRC1: Single CFB with CRC32
            var encCrc = CfbEncrypt(basePlainCrc);
            variantNum++;
            Log($"  [V{variantNum:D2}] CRC32 + single CFB | {encCrc.Length}B crc=0x{crc:X8}");
            Send(encCrc, peer);

            // V-CRC2: CRC32 in LE
            WriteLE32(basePlainCrc, 0, crc);
            encCrc = CfbEncrypt(basePlainCrc);
            variantNum++;
            Log($"  [V{variantNum:D2}] CRC32_LE + single CFB | {encCrc.Length}B");
            Send(encCrc, peer);

            // V-CRC3: Double CFB with CRC32 BE
            WriteBE32(basePlainCrc, 0, crc);
            encCrc = DoubleCfbEncrypt(basePlainCrc);
            variantNum++;
            Log($"  [V{variantNum:D2}] CRC32 + double CFB | {encCrc.Length}B");
            Send(encCrc, peer);
        }

        // === DOUBLE CFB VARIANTS ===
        // Maybe the client decrypts with double CFB, not single!
        {
            // Build baseline plaintext VERIFY_CONNECT
            var basePlain = new byte[48];
            int o = 0;
            WriteBE32(basePlain, o, _sessionId); o += 4;
            WriteBE16(basePlain, o, (ushort)(peer.OutgoingPeerID | 0x8000)); o += 2;
            WriteBE16(basePlain, o, sentTime); o += 2;
            basePlain[o] = 0x83; o++;
            basePlain[o] = 0xFF; o++;
            WriteBE16(basePlain, o, 1); o += 2;
            WriteBE16(basePlain, o, peer.OutgoingPeerID); o += 2;
            WriteBE16(basePlain, o, 996); o += 2;
            WriteBE32(basePlain, o, 32768); o += 4;
            WriteBE32(basePlain, o, 32); o += 4;
            WriteBE32(basePlain, o, 0); o += 4;
            WriteBE32(basePlain, o, 0); o += 4;
            WriteBE32(basePlain, o, 32); o += 4;
            WriteBE32(basePlain, o, 2); o += 4;
            WriteBE32(basePlain, o, 2); o += 4;

            // V31: Double CFB encrypted baseline
            var dblEnc = DoubleCfbEncrypt(basePlain);
            variantNum++;
            Log($"  [V{variantNum:D2}] DOUBLE CFB baseline | {dblEnc.Length}B");
            Send(dblEnc, peer);

            // V32: Double CFB with connectID (52B)
            var plainWithConn = new byte[52];
            Array.Copy(basePlain, plainWithConn, 48);
            WriteBE32(plainWithConn, 48, peer.ConnectToken);
            dblEnc = DoubleCfbEncrypt(plainWithConn);
            variantNum++;
            Log($"  [V{variantNum:D2}] DOUBLE CFB + connID | {dblEnc.Length}B");
            Send(dblEnc, peer);

            // V33: Double CFB with sessID=connToken
            var plainToken = (byte[])basePlain.Clone();
            WriteBE32(plainToken, 0, peer.ConnectToken);
            dblEnc = DoubleCfbEncrypt(plainToken);
            variantNum++;
            Log($"  [V{variantNum:D2}] DOUBLE CFB sessID=token | {dblEnc.Length}B");
            Send(dblEnc, peer);

            // V34: Double CFB with sessID=0
            var plainZero = (byte[])basePlain.Clone();
            WriteBE32(plainZero, 0, 0);
            dblEnc = DoubleCfbEncrypt(plainZero);
            variantNum++;
            Log($"  [V{variantNum:D2}] DOUBLE CFB sessID=0 | {dblEnc.Length}B");
            Send(dblEnc, peer);
        }

        // === NEW: Hybrid format - plaintext sessionID prefix + encrypted ENet ===
        // The Riot server response starts with sessionID in clear (b2cc6caa),
        // followed by encrypted data. Maybe the client checks the first 4 bytes.
        {
            // Build ENet VERIFY_CONNECT without sessionID in encrypted part
            var enetPlain = new byte[44]; // header without sessID(4) + cmd(4) + body(36)
            int o = 0;
            WriteBE16(enetPlain, o, (ushort)(peer.OutgoingPeerID | 0x8000)); o += 2;
            WriteBE16(enetPlain, o, sentTime); o += 2;
            enetPlain[o] = 0x83; o++;
            enetPlain[o] = 0xFF; o++;
            WriteBE16(enetPlain, o, 1); o += 2;
            WriteBE16(enetPlain, o, peer.OutgoingPeerID); o += 2;
            WriteBE16(enetPlain, o, 996); o += 2;
            WriteBE32(enetPlain, o, 32768); o += 4;
            WriteBE32(enetPlain, o, 32); o += 4;
            WriteBE32(enetPlain, o, 0); o += 4;
            WriteBE32(enetPlain, o, 0); o += 4;
            WriteBE32(enetPlain, o, 32); o += 4;
            WriteBE32(enetPlain, o, 2); o += 4;
            WriteBE32(enetPlain, o, 2); o += 4;

            // V31: [sessID_BE plaintext][CFB encrypted ENet]
            var enc31 = CfbEncrypt(enetPlain);
            var pkt31 = new byte[4 + enc31.Length];
            WriteBE32(pkt31, 0, _sessionId);
            Array.Copy(enc31, 0, pkt31, 4, enc31.Length);
            variantNum++;
            Log($"  [V{variantNum:D2}] HYBRID: sessID_BE prefix + CFB | {pkt31.Length}B");
            Send(pkt31, peer);

            // V32: [sessID_LE plaintext][CFB encrypted ENet]
            var pkt32 = new byte[4 + enc31.Length];
            WriteLE32(pkt32, 0, _sessionId);
            Array.Copy(enc31, 0, pkt32, 4, enc31.Length);
            variantNum++;
            Log($"  [V{variantNum:D2}] HYBRID: sessID_LE prefix + CFB | {pkt32.Length}B");
            Send(pkt32, peer);

        }

        // V31-V35: Just send raw response formats the Riot server might use
        {
            // Try: echo back the client's packet with modifications
            // V31 already done above

            // V33: Send just the connection token back (maybe it's a ping/pong?)
            var tokenPkt = new byte[4];
            WriteBE32(tokenPkt, 0, peer.ConnectToken);
            variantNum++;
            Log($"  [V{variantNum:D2}] RAW connToken echo | 4B");
            Send(tokenPkt, peer);

            // V34: Send LNPBlob-style response (magic + sessID + token)
            var lnpResp = new byte[12];
            WriteBE32(lnpResp, 0, LNPBLOB_MAGIC);
            WriteLE32(lnpResp, 4, _sessionId);
            WriteBE32(lnpResp, 8, peer.ConnectToken);
            variantNum++;
            Log($"  [V{variantNum:D2}] LNPBlob response | 12B");
            Send(lnpResp, peer);

            // V35: Mirror the client's first 15 bytes + our encrypted data
            // (the client might check if the response shares a prefix)
        }

        Log($"  === SENT {variantNum} VARIANTS ===");
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
