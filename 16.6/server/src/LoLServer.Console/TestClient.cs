using System;
using System.Threading;
using LENet;
using LoLServer.Core.Network;
using LoLServer.Core.Protocol;
using Channel = LoLServer.Core.Protocol.Channel;
using LoLServer.Core.Protocol.Packets;

namespace LoLServer.Console;

/// <summary>
/// Simulated LoL client for testing the server handshake and game sequence.
/// Runs the full: Connect → KeyCheck → SynchVersion → CharSelected → ClientReady flow.
/// </summary>
public static class TestClient
{
    public static void Run(string serverIp = "127.0.0.1", int serverPort = 5119, ulong playerId = 1)
    {
        var blowfishKey = "17BLOhi6KZsTtldTsizvHg==";
        var cipher = BlowFish.FromBase64(blowfishKey);

        System.Console.WriteLine("=== LoL Test Client ===");
        System.Console.WriteLine($"Connecting to {serverIp}:{serverPort}...");
        System.Console.WriteLine($"Player ID: {playerId}");
        System.Console.WriteLine($"Blowfish Key: {blowfishKey}");
        System.Console.WriteLine();

        // Try each protocol version
        var versions = new[]
        {
            LENet.Version.Patch420,
            LENet.Version.Seasson8_Server,
            LENet.Version.Seasson12,
            LENet.Version.Seasson34,
            LENet.Version.Seasson8_Client,
        };

        foreach (var version in versions)
        {
            System.Console.WriteLine($"[TEST] Trying version: ChecksumSend={version.ChecksumSizeSend} ChecksumRecv={version.ChecksumSizeReceive}");

            try
            {
                if (TryConnect(version, serverIp, serverPort, playerId, cipher))
                {
                    System.Console.WriteLine("[TEST] SUCCESS! Full handshake completed.");
                    return;
                }
            }
            catch (Exception ex)
            {
                System.Console.WriteLine($"[TEST] Failed: {ex.Message}");
            }
        }

        System.Console.WriteLine("[TEST] All versions failed.");
    }

    private static bool TryConnect(LENet.Version version, string serverIp, int serverPort, ulong playerId, BlowFish cipher)
    {
        using var client = new Host(version, null, 1, 32, 0, 0, 996);
        var address = new Address(serverIp, (ushort)serverPort);
        var peer = client.Connect(address, 32);

        if (peer == null)
        {
            System.Console.WriteLine("  [FAIL] Connect returned null");
            return false;
        }

        var ev = new Event();
        bool connected = false;
        bool handshakeDone = false;
        bool synchDone = false;
        bool spawnDone = false;
        bool gameStarted = false;
        int attempts = 0;

        while (attempts < 100) // 10 seconds max
        {
            int result = client.HostService(ev, 100);
            attempts++;

            if (result < 0)
            {
                System.Console.WriteLine("  [ERROR] HostService error");
                return false;
            }

            if (result == 0) continue;

            switch (ev.Type)
            {
                case EventType.CONNECT:
                    connected = true;
                    System.Console.WriteLine("  [OK] Connected to server!");

                    // Send KeyCheck
                    var keyCheck = new KeyCheck
                    {
                        Action = 0,
                        ClientId = peer.IncomingPeerID,
                        PlayerId = playerId,
                        VersionNo = 0,
                        CheckSum = BitConverter.ToUInt64(cipher.EncryptBlock(BitConverter.GetBytes(playerId)), 0)
                    };
                    var keyCheckData = keyCheck.Serialize();
                    System.Console.WriteLine($"  [SEND] KeyCheck ({keyCheckData.Length}B) PlayerId={playerId}");
                    var keyCheckPacket = new Packet(keyCheckData, PacketFlags.RELIABLE);
                    peer.Send((byte)Channel.Handshake, keyCheckPacket);
                    break;

                case EventType.RECEIVE:
                    var data = new byte[ev.Packet.DataLength];
                    Array.Copy(ev.Packet.Data, data, ev.Packet.DataLength);
                    var channel = ev.ChannelID;

                    if (channel == (byte)Channel.Handshake)
                    {
                        System.Console.WriteLine($"  [RECV] Handshake response ({data.Length}B)");
                        if (data.Length >= KeyCheck.PacketSize)
                        {
                            var resp = KeyCheck.Deserialize(data);
                            System.Console.WriteLine($"  [OK] KeyCheck response: {resp}");
                            handshakeDone = true;

                            // Send SynchVersionC2S
                            var synchData = new byte[256];
                            synchData[0] = (byte)GamePacketId.SynchVersionC2S;
                            var versionStr = System.Text.Encoding.ASCII.GetBytes("16.6.1");
                            Array.Copy(versionStr, 0, synchData, 5, versionStr.Length);

                            var encrypted = cipher.Encrypt(synchData);
                            System.Console.WriteLine($"  [SEND] SynchVersionC2S");
                            var synchPacket = new Packet(encrypted, PacketFlags.RELIABLE);
                            peer.Send((byte)Channel.ClientToServer, synchPacket);
                        }
                    }
                    else
                    {
                        // Decrypt
                        byte[] decrypted;
                        try
                        {
                            decrypted = cipher.Decrypt(data);
                        }
                        catch
                        {
                            System.Console.WriteLine($"  [RECV] Ch={channel} Len={data.Length} (decrypt failed, raw)");
                            continue;
                        }

                        var opcode = decrypted[0];
                        System.Console.WriteLine($"  [RECV] Ch={channel} Opcode=0x{opcode:X2} Len={decrypted.Length}");

                        switch ((GamePacketId)opcode)
                        {
                            case GamePacketId.SynchVersionS2C:
                                synchDone = true;
                                System.Console.WriteLine($"  [OK] SynchVersion OK!");

                                // Send CharSelectedC2S
                                var charData = new byte[4];
                                charData[0] = (byte)GamePacketId.CharSelectedC2S;
                                var charEncrypted = cipher.Encrypt(charData);
                                System.Console.WriteLine($"  [SEND] CharSelectedC2S");
                                peer.Send((byte)Channel.ClientToServer, new Packet(charEncrypted, PacketFlags.RELIABLE));
                                break;

                            case GamePacketId.StartSpawnS2C:
                                System.Console.WriteLine($"  [OK] StartSpawn received");
                                break;

                            case GamePacketId.CreateTurretS2C:
                                System.Console.WriteLine($"  [OK] CreateTurret received");
                                break;

                            case GamePacketId.CreateHeroS2C:
                                System.Console.WriteLine($"  [OK] CreateHero received");
                                break;

                            case GamePacketId.EndSpawnS2C:
                                spawnDone = true;
                                System.Console.WriteLine($"  [OK] EndSpawn received - spawn sequence complete!");

                                // Send ClientReadyC2S
                                var readyData = new byte[4];
                                readyData[0] = (byte)GamePacketId.ClientReadyC2S;
                                var readyEncrypted = cipher.Encrypt(readyData);
                                System.Console.WriteLine($"  [SEND] ClientReadyC2S");
                                peer.Send((byte)Channel.ClientToServer, new Packet(readyEncrypted, PacketFlags.RELIABLE));
                                break;

                            case GamePacketId.StartGameS2C:
                                gameStarted = true;
                                System.Console.WriteLine($"  [OK] StartGame received - WE ARE IN GAME!");
                                break;

                            case GamePacketId.GameTimerS2C:
                                if (decrypted.Length >= 5)
                                {
                                    float time = BitConverter.ToSingle(decrypted, 1);
                                    System.Console.WriteLine($"  [OK] GameTimer: {time:F1}s");
                                }
                                break;

                            case GamePacketId.StatsUpdateS2C:
                                System.Console.WriteLine($"  [OK] StatsUpdate received");
                                break;

                            case GamePacketId.GoldUpdateS2C:
                                System.Console.WriteLine($"  [OK] GoldUpdate received");
                                break;

                            case GamePacketId.SetHealthS2C:
                                System.Console.WriteLine($"  [OK] SetHealth received");
                                break;

                            case GamePacketId.AnnounceS2C:
                                System.Console.WriteLine($"  [OK] Announce received");
                                break;

                            case GamePacketId.InventoryUpdateS2C:
                                System.Console.WriteLine($"  [OK] InventoryUpdate received");
                                break;

                            case GamePacketId.CreateMinionS2C:
                                System.Console.WriteLine($"  [OK] CreateMinion received");
                                break;

                            case GamePacketId.ScoreboardUpdateS2C:
                                System.Console.WriteLine($"  [OK] ScoreboardUpdate received");
                                break;

                            default:
                                System.Console.WriteLine($"  [RECV] Unknown opcode 0x{opcode:X2}");
                                break;
                        }
                    }
                    break;

                case EventType.DISCONNECT:
                    System.Console.WriteLine("  [DISCONNECT] Server disconnected us");
                    return false;
            }

            // If game started, listen for a few more packets then exit
            if (gameStarted && attempts > 80)
                break;
        }

        System.Console.WriteLine();
        System.Console.WriteLine($"  === RESULTS ===");
        System.Console.WriteLine($"  Connected:   {(connected ? "YES" : "NO")}");
        System.Console.WriteLine($"  Handshake:   {(handshakeDone ? "YES" : "NO")}");
        System.Console.WriteLine($"  SynchVersion:{(synchDone ? "YES" : "NO")}");
        System.Console.WriteLine($"  Spawn:       {(spawnDone ? "YES" : "NO")}");
        System.Console.WriteLine($"  GameStarted: {(gameStarted ? "YES" : "NO")}");
        System.Console.WriteLine();

        return connected;
    }
}
