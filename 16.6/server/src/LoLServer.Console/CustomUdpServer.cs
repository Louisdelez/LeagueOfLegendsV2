using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using LoLServer.Core.Network;
using LoLServer.Core.Protocol.Packets;

namespace LoLServer.Console;

/// <summary>
/// Custom UDP server that handles the modern LoL client protocol directly,
/// without relying on LENet. Based on reverse-engineered packet captures.
///
/// Modern LoL client (16.6+) uses ENet with:
/// - 8-byte checksum header (often all zeros for CONNECT)
/// - Standard ENet commands after the checksum
/// - Blowfish encryption on game payload (after ENet handshake)
///
/// Packet format: [8B checksum][2B peerID][2B sentTime][ENet commands...]
/// </summary>
public static class CustomUdpServer
{
    private const int ChecksumSize = 8;
    private static BlowFish? _cipher;
    private static UdpClient? _socket;
    private static readonly Dictionary<string, PeerState> _peers = new();

    public static void Run(int port = 5119, string blowfishKey = "17BLOhi6KZsTtldTsizvHg==")
    {
        _cipher = BlowFish.FromBase64(blowfishKey);

        System.Console.WriteLine($"=== Custom UDP Game Server ===");
        System.Console.WriteLine($"Port: {port}");
        System.Console.WriteLine($"Blowfish Key: {blowfishKey}");
        System.Console.WriteLine($"Checksum size: {ChecksumSize} bytes");
        System.Console.WriteLine($"Waiting for LoL client connection...");
        System.Console.WriteLine();

        _socket = new UdpClient(port);
        int packetCount = 0;

        while (true)
        {
            IPEndPoint? remote = null;
            byte[] data;

            try
            {
                data = _socket.Receive(ref remote);
            }
            catch (SocketException ex)
            {
                Log($"[ERROR] {ex.Message}");
                continue;
            }

            packetCount++;
            var remoteKey = remote!.ToString();

            if (!_peers.ContainsKey(remoteKey))
            {
                _peers[remoteKey] = new PeerState { Remote = remote };
                Log($"[NEW PEER] {remoteKey}");
            }
            var peer = _peers[remoteKey];
            peer.LastPacketTime = DateTime.Now;
            peer.PacketCount++;

            // Parse the packet
            if (data.Length < ChecksumSize + 4)
            {
                Log($"[{remoteKey}] Packet too small ({data.Length}B)");
                continue;
            }

            // Extract checksum and ENet data
            var checksum = new byte[ChecksumSize];
            Array.Copy(data, 0, checksum, 0, ChecksumSize);

            var enetData = new byte[data.Length - ChecksumSize];
            Array.Copy(data, ChecksumSize, enetData, 0, enetData.Length);

            // Parse ENet header
            ushort peerID = (ushort)(enetData[0] | (enetData[1] << 8));
            ushort sentTime = (ushort)(enetData[2] | (enetData[3] << 8));

            if (packetCount <= 5 || packetCount % 50 == 0)
            {
                Log($"[{remoteKey}] #{packetCount} Len={data.Length} PeerID=0x{peerID:X4} SentTime={sentTime}");
            }

            // Parse ENet commands
            int offset = 4; // After peerID + sentTime
            while (offset < enetData.Length)
            {
                if (offset >= enetData.Length) break;

                byte cmdHeader = enetData[offset];
                int cmdType = cmdHeader & 0x0F;
                bool hasSentTime = (cmdHeader & 0x80) != 0;
                bool isCompressed = (cmdHeader & 0x40) != 0;

                if (cmdType == 0 || cmdType > 12) break; // Invalid command, stop parsing

                if (packetCount <= 5)
                {
                    Log($"  Cmd@{offset}: 0x{cmdHeader:X2} type={cmdType}({GetCmdName(cmdType)}) sentTime={hasSentTime} compressed={isCompressed}");
                }

                switch (cmdType)
                {
                    case 2: // CONNECT
                        HandleConnect(peer, enetData, offset, remote);
                        offset = enetData.Length; // Consume rest
                        break;
                    case 5: // PING
                        HandlePing(peer, enetData, offset, remote);
                        offset += 4;
                        break;
                    case 1: // ACK
                        offset += 8; // ACK is 8 bytes
                        break;
                    case 4: // DISCONNECT
                        Log($"  [DISCONNECT] Peer {remoteKey}");
                        _peers.Remove(remoteKey);
                        offset = enetData.Length;
                        break;
                    case 6: // RELIABLE
                        HandleReliable(peer, enetData, offset, remote);
                        offset = enetData.Length;
                        break;
                    default:
                        if (packetCount <= 5)
                            Log($"  [SKIP] Unknown cmd {cmdType} at offset {offset}");
                        offset = enetData.Length; // Can't parse further
                        break;
                }
            }
        }
    }

    static void HandleConnect(PeerState peer, byte[] enetData, int offset, IPEndPoint remote)
    {
        // CONNECT command: [1B header][1B channelID][2B reliableSeqNo]
        //   [2B outgoingPeerID][1B inSessionID][1B outSessionID]
        //   [4B mtu][4B windowSize][4B channelCount]
        //   [4B inBandwidth][4B outBandwidth]

        if (offset + 36 > enetData.Length)
        {
            Log($"  [CONNECT] Packet too small for CONNECT body");
            // The data might be encrypted. Try to handle it anyway.
            // For now, send a VERIFY_CONNECT with reasonable defaults
            SendVerifyConnect(peer, remote, 0xFFFF, 996, 32768, 32);
            return;
        }

        byte channelID = enetData[offset + 1];
        ushort reliableSeqNo = BitConverter.ToUInt16(enetData, offset + 2);
        ushort outgoingPeerID = BitConverter.ToUInt16(enetData, offset + 4);
        byte inSessionID = enetData[offset + 6];
        byte outSessionID = enetData[offset + 7];
        uint mtu = BitConverter.ToUInt32(enetData, offset + 8);
        uint windowSize = BitConverter.ToUInt32(enetData, offset + 12);
        uint channelCount = BitConverter.ToUInt32(enetData, offset + 16);
        uint inBandwidth = BitConverter.ToUInt32(enetData, offset + 20);
        uint outBandwidth = BitConverter.ToUInt32(enetData, offset + 24);

        Log($"  [CONNECT] outPeerID=0x{outgoingPeerID:X4} session={inSessionID}/{outSessionID} mtu={mtu} window={windowSize} channels={channelCount}");

        peer.OutgoingPeerID = outgoingPeerID;
        peer.SessionID = inSessionID;
        peer.MTU = mtu > 0 ? mtu : 996;
        peer.ChannelCount = channelCount > 0 ? channelCount : 32;
        peer.Connected = true;

        SendVerifyConnect(peer, remote, outgoingPeerID, peer.MTU, windowSize, peer.ChannelCount);
    }

    static void SendVerifyConnect(PeerState peer, IPEndPoint remote, ushort clientPeerID, uint mtu, uint windowSize, uint channelCount)
    {
        Log($"  [SEND] VERIFY_CONNECT to {remote}");

        // Build ENet VERIFY_CONNECT response
        // ENet header: [peerID:2][sentTime:2]
        // Command: [header:1][channelID:1][reliableSeqNo:2]
        // Body: [outPeerID:2][inSessionID:1][outSessionID:1][mtu:4][windowSize:4][channelCount:4][inBW:4][outBW:4]

        var response = new byte[ChecksumSize + 4 + 28];

        // 8-byte checksum = zeros (will compute later if needed)
        // ENet header
        int off = ChecksumSize;
        // PeerID = the client's outgoing peer ID (this is what the client expects us to address it as)
        response[off] = (byte)(clientPeerID & 0xFF);
        response[off + 1] = (byte)((clientPeerID >> 8) & 0xFF);
        // SentTime
        ushort time = (ushort)(Environment.TickCount & 0xFFFF);
        response[off + 2] = (byte)(time & 0xFF);
        response[off + 3] = (byte)((time >> 8) & 0xFF);

        // VERIFY_CONNECT command
        off += 4;
        response[off] = 0x83; // cmd=3(VERIFY_CONNECT) | flag=0x80(SENT_TIME)
        response[off + 1] = 0xFF; // channelID
        response[off + 2] = 0x01; // reliableSeqNo = 1
        response[off + 3] = 0x00;
        // outgoingPeerID (our peer ID for the client)
        response[off + 4] = 0x00;
        response[off + 5] = 0x00;
        // session IDs
        response[off + 6] = peer.SessionID;
        response[off + 7] = peer.SessionID;
        // mtu
        BitConverter.GetBytes(mtu).CopyTo(response, off + 8);
        // windowSize
        BitConverter.GetBytes(windowSize).CopyTo(response, off + 12);
        // channelCount
        BitConverter.GetBytes(channelCount).CopyTo(response, off + 16);
        // bandwidth (0 = no limit)
        BitConverter.GetBytes(0u).CopyTo(response, off + 20);
        BitConverter.GetBytes(0u).CopyTo(response, off + 24);

        try
        {
            _socket!.Send(response, response.Length, remote);
            Log($"  [SENT] VERIFY_CONNECT ({response.Length}B) to {remote}");
            Log($"    HEX: {BitConverter.ToString(response, 0, Math.Min(48, response.Length))}");
        }
        catch (Exception ex)
        {
            Log($"  [ERROR] Send failed: {ex.Message}");
        }
    }

    static void HandlePing(PeerState peer, byte[] enetData, int offset, IPEndPoint remote)
    {
        // Respond with ACK
        var ack = new byte[ChecksumSize + 4 + 8];
        int off = ChecksumSize;

        // PeerID
        ack[off] = (byte)(peer.OutgoingPeerID & 0xFF);
        ack[off + 1] = (byte)((peer.OutgoingPeerID >> 8) & 0xFF);
        // SentTime
        ushort time = (ushort)(Environment.TickCount & 0xFFFF);
        ack[off + 2] = (byte)(time & 0xFF);
        ack[off + 3] = (byte)((time >> 8) & 0xFF);

        // ACK command
        off += 4;
        ack[off] = 0x01; // ACK
        ack[off + 1] = 0xFF; // channelID
        // receivedReliableSeqNo
        ack[off + 2] = enetData[offset + 2];
        ack[off + 3] = enetData[offset + 3];
        // receivedSentTime
        ack[off + 4] = enetData[2]; // original sentTime
        ack[off + 5] = enetData[3];

        _socket!.Send(ack, ack.Length, remote);
    }

    static void HandleReliable(PeerState peer, byte[] enetData, int offset, IPEndPoint remote)
    {
        // RELIABLE: [header:1][channelID:1][reliableSeqNo:2][dataLength:2][data...]
        if (offset + 6 > enetData.Length) return;

        byte channelID = enetData[offset + 1];
        ushort seqNo = BitConverter.ToUInt16(enetData, offset + 2);
        ushort dataLen = BitConverter.ToUInt16(enetData, offset + 4);

        Log($"  [RELIABLE] channel={channelID} seq={seqNo} dataLen={dataLen}");

        if (offset + 6 + dataLen <= enetData.Length)
        {
            var payload = new byte[dataLen];
            Array.Copy(enetData, offset + 6, payload, 0, dataLen);

            // Channel 0 = Handshake (KeyCheck, unencrypted)
            if (channelID == 0)
            {
                Log($"  [HANDSHAKE] {dataLen}B: {BitConverter.ToString(payload, 0, Math.Min(32, payload.Length))}");

                if (dataLen >= KeyCheck.PacketSize)
                {
                    try
                    {
                        var keyCheck = KeyCheck.Deserialize(payload);
                        Log($"  [KEYCHECK] {keyCheck}");

                        // Verify and respond
                        if (_cipher != null)
                        {
                            bool valid = keyCheck.Verify(_cipher);
                            Log($"  [KEYCHECK] Valid: {valid}");

                            var resp = KeyCheck.CreateResponse(0, keyCheck.PlayerId, _cipher);
                            var respData = resp.Serialize();

                            // Send as reliable on channel 0
                            SendReliable(peer, remote, 0, respData, 1);
                            Log($"  [SENT] KeyCheck response!");
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"  [KEYCHECK] Parse failed: {ex.Message}");
                    }
                }
            }
            else
            {
                // Encrypted payload - decrypt with Blowfish
                try
                {
                    var decrypted = _cipher!.Decrypt(payload);
                    byte opcode = decrypted[0];
                    Log($"  [GAME] channel={channelID} opcode=0x{opcode:X2} decLen={decrypted.Length}");
                    Log($"    First16: {BitConverter.ToString(decrypted, 0, Math.Min(16, decrypted.Length))}");
                }
                catch
                {
                    Log($"  [GAME] channel={channelID} (decrypt failed, raw: {BitConverter.ToString(payload, 0, Math.Min(16, payload.Length))})");
                }
            }
        }

        // Send ACK for the reliable packet
        SendAck(peer, remote, channelID, seqNo);
    }

    static void SendReliable(PeerState peer, IPEndPoint remote, byte channelID, byte[] payload, ushort seqNo)
    {
        var packet = new byte[ChecksumSize + 4 + 6 + payload.Length];
        int off = ChecksumSize;

        // ENet header
        packet[off] = (byte)(peer.OutgoingPeerID & 0xFF);
        packet[off + 1] = (byte)((peer.OutgoingPeerID >> 8) & 0xFF);
        ushort time = (ushort)(Environment.TickCount & 0xFFFF);
        packet[off + 2] = (byte)(time & 0xFF);
        packet[off + 3] = (byte)((time >> 8) & 0xFF);

        // RELIABLE command
        off += 4;
        packet[off] = 0x86; // cmd=6(RELIABLE) | flag=0x80(SENT_TIME)
        packet[off + 1] = channelID;
        BitConverter.GetBytes(seqNo).CopyTo(packet, off + 2);
        BitConverter.GetBytes((ushort)payload.Length).CopyTo(packet, off + 4);
        Array.Copy(payload, 0, packet, off + 6, payload.Length);

        _socket!.Send(packet, packet.Length, remote);
    }

    static void SendAck(PeerState peer, IPEndPoint remote, byte channelID, ushort seqNo)
    {
        var ack = new byte[ChecksumSize + 4 + 8];
        int off = ChecksumSize;

        ack[off] = (byte)(peer.OutgoingPeerID & 0xFF);
        ack[off + 1] = (byte)((peer.OutgoingPeerID >> 8) & 0xFF);
        ushort time = (ushort)(Environment.TickCount & 0xFFFF);
        ack[off + 2] = (byte)(time & 0xFF);
        ack[off + 3] = (byte)((time >> 8) & 0xFF);

        off += 4;
        ack[off] = 0x01; // ACK
        ack[off + 1] = channelID;
        BitConverter.GetBytes(seqNo).CopyTo(ack, off + 2);
        BitConverter.GetBytes(time).CopyTo(ack, off + 4);

        _socket!.Send(ack, ack.Length, remote);
    }

    static string GetCmdName(int cmd) => cmd switch
    {
        1 => "ACK", 2 => "CONNECT", 3 => "VERIFY_CONNECT", 4 => "DISCONNECT",
        5 => "PING", 6 => "RELIABLE", 7 => "UNRELIABLE", 8 => "FRAGMENT",
        9 => "UNSEQUENCED", 10 => "BW_LIMIT", 11 => "THROTTLE", 12 => "UNRELIABLE_FRAG",
        _ => $"?({cmd})"
    };

    static void Log(string msg)
    {
        System.Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] {msg}");
    }
}

class PeerState
{
    public IPEndPoint Remote { get; set; } = null!;
    public ushort OutgoingPeerID { get; set; }
    public byte SessionID { get; set; }
    public uint MTU { get; set; } = 996;
    public uint ChannelCount { get; set; } = 32;
    public bool Connected { get; set; }
    public int PacketCount { get; set; }
    public DateTime LastPacketTime { get; set; }
}
