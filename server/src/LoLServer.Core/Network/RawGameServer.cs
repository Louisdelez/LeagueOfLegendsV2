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

        // Extract connection token from bytes 8-11 (4B unencrypted header)
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

        // Format: [8B LNPBlob][4B conn header UNENCRYPTED][Double-CFB encrypted: [4B CRC nonce][1B flags/cmd][body...]]
        // conn+0x144=4 means first 4 bytes after LNPBlob are NOT encrypted
        int headerSkip = 4; // connection header (unencrypted)
        if (data.Length > 8 + headerSkip)
        {
            int encLen = data.Length - 8 - headerSkip;
            byte[] encPayload = new byte[encLen];
            Array.Copy(data, 8 + headerSkip, encPayload, 0, encLen);

            byte[] dec = DoubleCfbDecrypt(encPayload);

            // After decrypt: [4B CRC nonce][1B flags/cmd][body...]
            if (dec.Length >= 5)
            {
                uint nonce = (uint)(dec[0] | (dec[1] << 8) | (dec[2] << 16) | (dec[3] << 24));
                byte flags = dec[4];
                byte cmdType = (byte)(flags & 0x0F); // low 4 bits = command type (proven working)
                int bodyStart = 5;
                int bodyLen = dec.Length - bodyStart;

                if (peer.PacketCount <= 100)
                {
                    Log($"  [DECRYPT] nonce=0x{nonce:X8} flags=0x{flags:X2} cmd={cmdType} bodyLen={bodyLen}");
                    Log($"  [BODY] {Hex(dec, bodyStart, Math.Min(128, bodyLen))}");
                }

                // Store decoded payload for analysis
                if (bodyLen > 0)
                {
                    byte[] body = new byte[bodyLen];
                    Array.Copy(dec, bodyStart, body, 0, bodyLen);
                    peer.LastDecryptedBody = body;
                    peer.LastCmd = cmdType;

                    // Scan ALL bodies ≥ 20 bytes for KeyCheck pattern (action=0, valid playerID)
                    // KeyCheck: [1B action=0][3B pad=0][4B clientID][8B playerID][8B unused][8B checksum]
                    if (!peer.KeyCheckDone && bodyLen >= 32)
                    {
                        // Search for KeyCheck pattern in the body
                        for (int koff = 0; koff + 32 <= bodyLen; koff++)
                        {
                            if (body[koff] == 0x00 && body[koff+1] == 0x00 && body[koff+2] == 0x00 && body[koff+3] == 0x00)
                            {
                                // Check if bytes 8-15 contain a small playerID (1-10)
                                ulong pid = BitConverter.ToUInt64(body, koff + 8);
                                if (pid >= 1 && pid <= 100)
                                {
                                    Log($"  [KEYCHECK-SCAN] Found KeyCheck at body+{koff}: playerID={pid}");
                                    byte[] kcData = new byte[32];
                                    Array.Copy(body, koff, kcData, 0, 32);
                                    HandleKeyCheckFromClient(kcData, peer);
                                    peer.KeyCheckDone = true;
                                    break;
                                }
                            }
                        }
                    }

                    // Parse game data from cmd=2 (batch) packets
                    if (cmdType == 2 && bodyLen > 6)
                    {
                        ParseClientBatch(body, peer);
                    }
                    // Parse game packets from all other commands
                    else if (cmdType != 1 && cmdType != 5 && bodyLen > 4) // skip ACK(1) and PING(5)
                    {
                        ParseClientGamePacket(body, peer, cmdType);
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
        // HYBRID: Echo + CAFE ACK + CAFE game data
        // Echo: returns client's own data (ENet state machine)
        if (data.Length > 12)
        {
            int echoLen = data.Length - 8;
            var echo = new byte[echoLen];
            Array.Copy(data, 8, echo, 0, echoLen);
            Send(echo, peer);
        }
        // Send ACK for every client packet (incrementing seqNo)
        // This tells ENet "I received your reliable packet N"
        {
            var ackBody = new byte[4];
            WriteBE16(ackBody, 0, peer.AckSeqNo++); // seqNo to ACK
            WriteBE16(ackBody, 2, (ushort)(peer.PacketCount & 0xFFFF)); // sentTime
            SendCrcPacket(peer, 0x01, ackBody); // cmd=1 ACKNOWLEDGE
        }
        // Also send CAFE responses
        if (peer.PacketCount <= 3)
        {
            // VERIFY_CONNECT with 8 channels
            var vcBody = new byte[36];
            WriteBE16(vcBody, 0, 1);      // outPeerID = 1 (not 0!)
            vcBody[2] = 0x00;             // incomingSessionID = 0
            vcBody[3] = 0x00;             // outgoingSessionID = 0
            WriteBE32(vcBody, 4, 996);    // MTU
            WriteBE32(vcBody, 8, 32768);  // windowSize
            WriteBE32(vcBody, 12, 8);     // channelCount = 8
            WriteBE32(vcBody, 16, 0);     // inBandwidth
            WriteBE32(vcBody, 20, 0);     // outBandwidth
            WriteBE32(vcBody, 24, 5000);  // throttleInterval
            WriteBE32(vcBody, 28, 2);     // throttleAccel
            WriteBE32(vcBody, 32, 2);     // throttleDecel
            SendCrcPacket(peer, 0x03, vcBody); // cmd=3 VERIFY_CONNECT
        }
        else if (peer.PacketCount <= 6)
        {
            // Send ACK for client's packets (cmd=1)
            // ACK body: [2B seqNo BE][2B sentTime BE]
            var ackBody = new byte[4];
            WriteBE16(ackBody, 0, (ushort)(peer.PacketCount - 1)); // seqNo
            WriteBE16(ackBody, 2, 0); // sentTime = 0
            SendCrcPacket(peer, 0x01, ackBody); // cmd=1 ACKNOWLEDGE
        }
        else
        {
            // Keepalive: alternate between PING and ACK
            if (peer.PacketCount % 2 == 0)
                SendCrcPacket(peer, 0x05, new byte[0]); // PING
            else {
                var ackBody = new byte[4];
                WriteBE16(ackBody, 0, (ushort)(peer.PacketCount / 2));
                WriteBE16(ackBody, 2, 0);
                SendCrcPacket(peer, 0x01, ackBody); // ACK
            }
        }

        // === GAME DATA (heap scan disabled in hook — game stays alive) ===
        // Send game init sequence at the right time
        if (peer.PacketCount % 100 == 0)
            Log($"  [STATUS] pkt#{peer.PacketCount} — game alive");

        // After handshake, send game init packets
        // Try both RAW and BATCH formats, and both old (S4) and potential modern opcodes
        if (peer.PacketCount == 15 && !peer.GameInitSent)
        {
            peer.GameInitSent = true;
            Log($"  [GAME-INIT] Sending full init sequence with 16.6 opcodes");

            // === Send SynchVersionS2C using ALL handled opcodes (brute force) ===
            // The dispatcher handles these opcodes: 0x0A,0x0C,0x16,0x19,0x2A,0x33,0x38,
            // 0x4F,0x56,0x71,0x86,0x8B,0xAA,0xAD,0xAE,0xB4,0xC7,0xCB,0xD4,0xD5,0xE5,0x103
            // One of them is the SynchVersionS2C. Send a SynchVersion-like response
            // using each opcode that could be the S2C version.

            // Format: [1B opcode][4B netID=0][body...] for opcodes < 0xFE
            //    OR:  [0xFE][4B netID=0][2B opcode LE][body...] for extended opcodes

            // SynchVersionS2C body: [4B isOK=1][version string at offset ~128][4B mapId][4B playerCount]
            byte[] synchBody = new byte[506]; // body after opcode+netID header
            BitConverter.GetBytes(1u).CopyTo(synchBody, 0); // isVersionOK = 1
            var verBytes = System.Text.Encoding.ASCII.GetBytes(_config.GameVersion ?? "16.6.1");
            Array.Copy(verBytes, 0, synchBody, 128, Math.Min(verBytes.Length, 127));
            BitConverter.GetBytes(_config.MapId).CopyTo(synchBody, 256);
            BitConverter.GetBytes(_config.Players.Count).CopyTo(synchBody, 260);

            // Try each handled opcode as the SynchVersionS2C response
            ushort[] handledOpcodes = { 0x0A, 0x0C, 0x16, 0x19, 0x2A, 0x33, 0x38,
                0x4F, 0x56, 0x71, 0x86, 0x8B, 0xAA, 0xAD, 0xAE, 0xB4,
                0xC7, 0xCB, 0xD4, 0xD5, 0xE5, 0x103 };

            // Send SynchVersionS2C with MULTIPLE framing methods:
            // Method 1: Raw game data via cmd=2 (current approach)
            // Method 2: Reliable on channel 1 (ClientToServer response)
            // Method 3: Reliable on channel 3 (ServerToClient)
            // Method 4: Different flag encodings

            // Use likely SynchVersion opcodes: 0x54 (S4), 0x1B (our enum),
            // and each dispatcher-handled opcode
            ushort[] likelyOpcodes = { 0x54, 0x1B, 0x0A, 0x0C, 0x19, 0x56, 0x86, 0xD4, 0xD5 };

            foreach (var opc in likelyOpcodes)
            {
                // Standard game packet: [1B opcode][4B netID=0][body...]
                var pkt = new byte[Math.Min(512, 5 + synchBody.Length)];
                pkt[0] = (byte)(opc & 0xFF);
                Array.Copy(synchBody, 0, pkt, 5, Math.Min(synchBody.Length, pkt.Length - 5));

                // Method 1: raw cmd=2
                SendGamePacket(peer, pkt, $"Synch-raw-0x{opc:X2}");

                // Method 2: batch cmd=2
                SendBatchPacket(peer, pkt, $"Synch-batch-0x{opc:X2}");

                // Method 3: reliable on channel 3 (ServerToClient)
                SendReliableOnChannel(peer, 3, pkt);
            }

            Log($"  [GAME-INIT] Sent {likelyOpcodes.Length} SynchVersion candidates x3 methods");

            // === Also try KeyCheck response on channel 0 ===
            var keyCheck = new byte[32];
            keyCheck[0] = 0x00; // action = response
            keyCheck[8] = 0x01; // playerID = 1
            var playerIdBytes = new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            var encrypted = _cipher.EncryptBlock(playerIdBytes);
            Array.Copy(encrypted, 0, keyCheck, 20, 8);
            SendGamePacket(peer, keyCheck, "KeyCheck-raw");
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
    //  SEND GAME PACKETS
    // ========================================================================

    /// <summary>
    /// Send a game packet via cmd=2 (game data path → handler +0x168).
    /// Sends RAW game data (no batch framing) — the handler at +0x168 may expect
    /// either batch-framed or raw GamePacket format.
    /// </summary>
    private void SendGamePacket(PeerInfo peer, byte[] gameData, string description)
    {
        // Send raw game data via cmd=2 (no batch framing)
        SendCrcPacket(peer, 0x02, gameData);
        Log($"  [GAME-PKT] {description}: {gameData.Length}B raw, cmd=0x02");
    }

    /// <summary>
    /// Send a game packet wrapped in batch framing via cmd=2.
    /// Batch format: [0x02][u32 total_dwords][sub: u32 dword_count + data][0x18]
    /// </summary>
    private void SendBatchPacket(PeerInfo peer, byte[] gameData, string description)
    {
        int paddedLen = (gameData.Length + 3) & ~3;
        var padded = new byte[paddedLen];
        Array.Copy(gameData, 0, padded, 0, gameData.Length);
        int dwordCount = paddedLen / 4;

        var batch = new System.IO.MemoryStream();
        batch.WriteByte(0x02);
        batch.Write(BitConverter.GetBytes((uint)dwordCount), 0, 4);
        batch.Write(BitConverter.GetBytes((uint)dwordCount), 0, 4);
        batch.Write(padded, 0, paddedLen);
        batch.WriteByte(0x18);

        var batchData = batch.ToArray();
        SendCrcPacket(peer, 0x02, batchData);
        Log($"  [BATCH-PKT] {description}: {gameData.Length}B data, {batchData.Length}B batch, cmd=0x02");
    }

    // ========================================================================
    //  CLIENT GAME PACKET PARSING
    // ========================================================================

    /// <summary>
    /// Parse batch-framed game data from cmd=2 body.
    /// Format: [0x02][u32 LE total_dword_count][sub-packets...][0x18]
    /// Each sub-packet: [u32 LE dword_count][dword_count * 4 bytes of data]
    /// Opcode is at byte offset 50 of each 56-byte (14 DWORD) record.
    /// </summary>
    private void ParseClientBatch(byte[] body, PeerInfo peer)
    {
        if (body[0] != 0x02) return;
        if (body.Length < 6) return;

        uint totalDwords = BitConverter.ToUInt32(body, 1);
        Log($"  [CLIENT-BATCH] marker=0x02 totalDwords={totalDwords} bodyLen={body.Length}");

        int offset = 5; // skip marker(1) + totalDwords(4)
        int recordNum = 0;
        while (offset + 4 <= body.Length && body[offset] != 0x18)
        {
            uint dwordCount = BitConverter.ToUInt32(body, offset);
            int dataLen = (int)(dwordCount * 4);
            offset += 4;

            if (dataLen <= 0 || offset + dataLen > body.Length) break;

            recordNum++;
            byte[] record = new byte[dataLen];
            Array.Copy(body, offset, record, 0, dataLen);

            // Extract fields from the record
            if (dataLen >= 52) // need at least 52 bytes for opcode at offset 50
            {
                ushort opcode = (ushort)(record[50] | (record[51] << 8));
                uint netId = BitConverter.ToUInt32(record, 0);
                Log($"  [CLIENT-OPCODE] #{recordNum} opcode=0x{opcode:X4} netID=0x{netId:X8} dwords={dwordCount} data={Hex(record, 0, Math.Min(56, dataLen))}");

                // Track client opcodes for response
                HandleClientGameOpcode(opcode, record, peer);
            }
            else
            {
                Log($"  [CLIENT-RECORD] #{recordNum} dwords={dwordCount} data={Hex(record, 0, Math.Min(32, dataLen))}");
            }

            offset += dataLen;
        }

        if (offset < body.Length)
            Log($"  [CLIENT-BATCH] terminator=0x{body[Math.Min(offset, body.Length - 1)]:X2}");
    }

    /// <summary>
    /// Parse a game packet from reliable channel data.
    /// LeagueSandbox format: [1B opcode][4B senderNetID][body...]
    /// Extended: [0xFE][4B senderNetID][2B opcode LE][body...]
    /// Batched: [0xFF][1B count][packets...]
    /// </summary>
    private void ParseClientGamePacket(byte[] gameData, PeerInfo peer, byte channel)
    {
        if (gameData.Length < 1) return;

        byte firstByte = gameData[0];

        if (firstByte == 0xFE && gameData.Length >= 7)
        {
            // Extended opcode format
            uint netId = BitConverter.ToUInt32(gameData, 1);
            ushort opcode = BitConverter.ToUInt16(gameData, 5);
            Log($"  [CLIENT-GAME] EXTENDED opcode=0x{opcode:X4} netID=0x{netId:X8} ch={channel} len={gameData.Length}");
            Log($"  [CLIENT-GAME-DATA] {Hex(gameData, 0, Math.Min(64, gameData.Length))}");
            HandleClientGameOpcode(opcode, gameData, peer);
        }
        else if (firstByte == 0xFF && gameData.Length >= 2)
        {
            // Batched packets
            byte count = gameData[1];
            Log($"  [CLIENT-GAME] BATCHED count={count} ch={channel} len={gameData.Length}");
            Log($"  [CLIENT-GAME-DATA] {Hex(gameData, 0, Math.Min(64, gameData.Length))}");
        }
        else if (gameData.Length >= 5)
        {
            // Normal opcode (1 byte)
            byte opcode = firstByte;
            uint netId = BitConverter.ToUInt32(gameData, 1);
            Log($"  [CLIENT-GAME] NORMAL opcode=0x{opcode:X2} netID=0x{netId:X8} ch={channel} len={gameData.Length}");
            Log($"  [CLIENT-GAME-DATA] {Hex(gameData, 0, Math.Min(64, gameData.Length))}");
            HandleClientGameOpcode(opcode, gameData, peer);
        }
        else
        {
            Log($"  [CLIENT-GAME] SHORT ch={channel} len={gameData.Length} data={Hex(gameData, 0, gameData.Length)}");
            // Short packets (2-4 bytes) might contain opcode data in different format
            // Pattern seen: [2B seq][0xFE][1B opcode_lo] — extended opcode in 4-byte packet
            if (gameData.Length == 4 && gameData[2] == 0xFE)
            {
                ushort opcode = gameData[3]; // single byte opcode after FE marker
                Log($"  [CLIENT-GAME] SHORT-EXT opcode=0x{opcode:X4} seq={gameData[0]:X2}{gameData[1]:X2}");
                HandleClientGameOpcode(opcode, gameData, peer);
            }
            // Or maybe the entire 4 bytes is the game data with opcode at byte 0
            else if (gameData.Length >= 2)
            {
                ushort opcode = gameData[0];
                Log($"  [CLIENT-GAME] SHORT-NORM opcode=0x{opcode:X2}");
                HandleClientGameOpcode(opcode, gameData, peer);
            }
        }
    }

    /// <summary>
    /// Handle KeyCheck from the client on channel 0 (handshake).
    /// KeyCheck format: [1B action][3B pad][4B clientID][8B playerID][8B unused][8B checksum(BF encrypted)]
    /// We respond with a KeyCheck response and then wait for SynchVersion.
    /// </summary>
    private void HandleKeyCheckFromClient(byte[] data, PeerInfo peer)
    {
        // Try to parse as KeyCheck
        try
        {
            var kc = Protocol.Packets.KeyCheck.Deserialize(data);
            Log($"  [KEYCHECK] Parsed: Action={kc.Action} ClientId={kc.ClientId} PlayerId={kc.PlayerId}");

            // Create KeyCheck response
            var client = EnsureClientInfo(peer);
            client.PlayerId = kc.PlayerId;
            client.State = ClientState.Authenticated;

            var resp = Protocol.Packets.KeyCheck.CreateResponse(client.ClientId, kc.PlayerId, _cipher);
            var respBytes = resp.Serialize();
            Log($"  [KEYCHECK] Sending response ({respBytes.Length}B)");

            // Send KeyCheck response on channel 0 (reliable)
            // Use cmd=6 channel=0 (reliable on handshake channel)
            SendReliableOnChannel(peer, 0, respBytes);

            Log($"  [KEYCHECK] *** KeyCheck handshake complete! Client authenticated. ***");
        }
        catch (Exception ex)
        {
            Log($"  [KEYCHECK] Parse failed: {ex.Message}");
            Log($"  [KEYCHECK] Raw data ({data.Length}B): {Hex(data, 0, Math.Min(32, data.Length))}");

            // Try to respond with a basic KeyCheck response anyway
            var client = EnsureClientInfo(peer);
            var respBytes = new byte[32];
            respBytes[0] = 0x01; // action = response
            BitConverter.GetBytes(client.ClientId).CopyTo(respBytes, 4);
            var playerIdBytes = BitConverter.GetBytes(1UL); // player ID 1
            playerIdBytes.CopyTo(respBytes, 8);
            var encrypted = _cipher.EncryptBlock(playerIdBytes);
            Array.Copy(encrypted, 0, respBytes, 20, Math.Min(8, encrypted.Length));
            SendReliableOnChannel(peer, 0, respBytes);
            Log($"  [KEYCHECK] Sent fallback response ({respBytes.Length}B)");
        }
    }

    /// <summary>
    /// Send data as reliable on a specific ENet channel.
    /// Wraps data in ENet reliable command format.
    /// </summary>
    private void SendReliableOnChannel(PeerInfo peer, byte channel, byte[] data)
    {
        // Build reliable header: [1B channel][2B seqNo BE][2B dataLen BE][data]
        var reliable = new byte[5 + data.Length];
        reliable[0] = channel;
        reliable[1] = 0; reliable[2] = 1; // seqNo = 1
        reliable[3] = (byte)((data.Length >> 8) & 0xFF);
        reliable[4] = (byte)(data.Length & 0xFF);
        Array.Copy(data, 0, reliable, 5, data.Length);

        // Send via CRC packet with flags = 0x60 (cmd=6 reliable, channel=0)
        byte flagByte = (byte)((6 << 4) | (channel & 0x0F));
        SendCrcPacket(peer, flagByte, reliable);
        Log($"  [SEND-RELIABLE] ch={channel} flags=0x{flagByte:X2} payload={data.Length}B");
    }

    /// <summary>
    /// Handle a game opcode from the client and send appropriate response.
    /// Protocol is CLIENT-DRIVEN: client sends requests, server responds.
    /// Opcodes are from Season 4 LeagueSandbox but may differ in modern client.
    /// We log everything and respond to recognized patterns.
    /// </summary>
    private void HandleClientGameOpcode(ushort opcode, byte[] data, PeerInfo peer)
    {
        // Track all client opcodes we see
        if (!peer.SeenOpcodes.Contains(opcode))
        {
            peer.SeenOpcodes.Add(opcode);
            Log($"  [NEW-OPCODE] Client sent opcode 0x{opcode:X4} for the first time! Total unique: {peer.SeenOpcodes.Count}");
        }

        // Modern client (16.6) uses extended opcode format: [0xFE][4B netID][2B opcode LE][body]
        // Client sends opcode 0x002C every 2 seconds = likely SynchVersionC2S
        // Respond with SynchVersionS2C using the same extended format

        if (opcode == 0x002C || opcode == 0x56 || opcode == 0xBD) // SynchVersion (modern + legacy)
        {
            Log($"  [SYNCH] Received SynchVersion (opcode 0x{opcode:X4}), sending response...");

            // SynchVersionS2C — respond using extended opcode format
            // Format: [0xFE][4B netID=0][2B opcode=0x001B][body]
            // The body contains: version string, map ID, player list
            var resp = new byte[512];
            resp[0] = 0xFE; // extended opcode marker
            // netID = 0 at [1..4]
            resp[5] = 0x1B; // opcode low byte (SynchVersionS2C = 0x1B)
            resp[6] = 0x00; // opcode high byte
            // Body: bitfield + map + version string
            resp[7] = 0x01; // isVersionOK = true
            resp[8] = (byte)(_config.MapId & 0xFF); // map ID low
            resp[9] = (byte)((_config.MapId >> 8) & 0xFF);
            // Version string at offset ~298-7=291 from body start, i.e. at byte 298
            var verStr = System.Text.Encoding.ASCII.GetBytes($"Version {_config.GameVersion}");
            Array.Copy(verStr, 0, resp, 298, Math.Min(verStr.Length, 200));
            SendGamePacket(peer, resp, "SynchVersionS2C-response");

            // Also send as batch in case client expects batch format
            SendBatchPacket(peer, resp, "SynchVersionS2C-batch");
        }
        else if (opcode == 0x0014 || opcode == 0x88) // QueryStatus
        {
            Log($"  [QUERY] QueryStatus (0x{opcode:X4}), sending response");
            var ans = new byte[] { 0x88, 0x00, 0x00, 0x00, 0x00, 0x01 };
            SendGamePacket(peer, ans, "QueryStatusAns");
        }
        else
        {
            Log($"  [UNHANDLED] Client opcode 0x{opcode:X4}, data: {Hex(data, 0, Math.Min(32, data.Length))}");
        }
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
        public ushort AckSeqNo { get; set; } = 0;
        public byte[]? LastDecryptedBody { get; set; }
        public byte LastCmd { get; set; }
        public HashSet<ushort> SeenOpcodes { get; set; } = new();
        public bool KeyCheckDone { get; set; }
    }
}
