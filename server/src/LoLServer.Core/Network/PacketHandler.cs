using System;
using System.Text;
using System.Threading;
using LoLServer.Core.Config;
using LoLServer.Core.Game;
using LoLServer.Core.Game.Entities;
using LoLServer.Core.Protocol;

namespace LoLServer.Core.Network;

/// <summary>
/// Routes decrypted packets to the appropriate handler based on channel and opcode.
/// Implements the handshake/loading/game sequence.
/// </summary>
public class PacketHandler
{
    private readonly GameConfig _config;
    private readonly PacketServer _server;
    private GameLoop? _gameLoop;
    private Thread? _gameThread;

    public PacketHandler(GameConfig config, PacketServer server)
    {
        _config = config;
        _server = server;
    }

    public void HandlePacket(byte[] data, Channel channel, ClientInfo client)
    {
        if (data.Length == 0)
        {
            Log($"[HANDLER] Empty packet on channel {channel}");
            return;
        }

        var opcode = data[0];
        Log($"[HANDLER] Channel={channel} Opcode=0x{opcode:X2} Len={data.Length} Client={client.ClientId} State={client.State}");

        switch (channel)
        {
            case Channel.ClientToServer:
                HandleC2S(opcode, data, client);
                break;

            case Channel.Gameplay:
                HandleGameplay(opcode, data, client);
                break;

            case Channel.LoadingScreen:
                HandleLoadingScreen(opcode, data, client);
                break;

            case Channel.Communication:
                HandleChat(opcode, data, client);
                break;

            default:
                Log($"  [UNKNOWN] Unhandled channel {channel}, opcode 0x{opcode:X2}");
                LogHex(data);
                break;
        }
    }

    private void HandleC2S(byte opcode, byte[] data, ClientInfo client)
    {
        switch ((GamePacketId)opcode)
        {
            case GamePacketId.SynchVersionC2S:
                HandleSynchVersion(data, client);
                break;

            case GamePacketId.PingLoadInfoC2S:
                HandlePingLoadInfo(data, client);
                break;

            case GamePacketId.CharSelectedC2S:
                HandleCharSelected(data, client);
                break;

            case GamePacketId.ClientReadyC2S:
                HandleClientReady(data, client);
                break;

            default:
                Log($"  [C2S] Unknown opcode 0x{opcode:X2}");
                LogHex(data);
                break;
        }
    }

    private void HandleGameplay(byte opcode, byte[] data, ClientInfo client)
    {
        Log($"  [GAMEPLAY] Opcode=0x{opcode:X2} Len={data.Length}");
        LogHex(data);
    }

    private void HandleLoadingScreen(byte opcode, byte[] data, ClientInfo client)
    {
        switch ((LoadScreenPacketId)opcode)
        {
            case LoadScreenPacketId.RequestJoinTeam:
                HandleRequestJoinTeam(data, client);
                break;

            case LoadScreenPacketId.RequestReskin:
                HandleRequestReskin(data, client);
                break;

            case LoadScreenPacketId.RequestRename:
                HandleRequestRename(data, client);
                break;

            default:
                Log($"  [LOADING] Unknown opcode 0x{opcode:X2}");
                LogHex(data);
                break;
        }
    }

    private void HandleChat(byte opcode, byte[] data, ClientInfo client)
    {
        Log($"  [CHAT] From client {client.ClientId}: opcode 0x{opcode:X2}");
        LogHex(data);
    }

    // ======= Packet Handlers =======

    private void HandleSynchVersion(byte[] data, ClientInfo client)
    {
        Log($"  [SYNCH] Client requests version sync");

        // Build SynchVersionS2C response
        // Format: [1B opcode][4B isVersionOk][128B gameVersion][...playerInfo]
        var response = new byte[512];
        response[0] = (byte)GamePacketId.SynchVersionS2C;

        // Version OK = 1
        BitConverter.GetBytes(1u).CopyTo(response, 1);

        // Game version string (null-terminated, 128 bytes max)
        var versionBytes = Encoding.ASCII.GetBytes(_config.GameVersion);
        Array.Copy(versionBytes, 0, response, 5, Math.Min(versionBytes.Length, 127));

        // Map ID
        BitConverter.GetBytes(_config.MapId).CopyTo(response, 133);

        // Player count
        BitConverter.GetBytes(_config.Players.Count).CopyTo(response, 137);

        _server.SendPacket(client, response, Channel.ServerToClient);
        Log($"  [SYNCH] Sent SynchVersionS2C (version={_config.GameVersion}, map={_config.MapId})");
    }

    private void HandlePingLoadInfo(byte[] data, ClientInfo client)
    {
        // Client sends loading progress
        if (data.Length >= 5)
        {
            var progress = BitConverter.ToSingle(data, 1);
            client.LoadingProgress = progress;
            Log($"  [LOAD] Client {client.ClientId} loading: {progress:P0}");

            // Relay loading info to all clients
            var response = new byte[data.Length];
            response[0] = (byte)GamePacketId.PingLoadInfoS2C;
            Array.Copy(data, 1, response, 1, data.Length - 1);
            _server.BroadcastPacket(response, Channel.ServerToClient);
        }
    }

    private void HandleCharSelected(byte[] data, ClientInfo client)
    {
        Log($"  [CHAR] Client {client.ClientId} selected champion");
        client.State = ClientState.Loading;

        // Send StartSpawn
        var startSpawn = new byte[] { (byte)GamePacketId.StartSpawnS2C, 0x00 };
        _server.SendPacket(client, startSpawn, Channel.ServerToClient);

        // TODO: Send champion spawn data, turret spawns, etc.

        // Send EndSpawn
        var endSpawn = new byte[] { (byte)GamePacketId.EndSpawnS2C, 0x00 };
        _server.SendPacket(client, endSpawn, Channel.ServerToClient);

        Log($"  [SPAWN] Sent StartSpawn -> EndSpawn to client {client.ClientId}");
    }

    private void HandleClientReady(byte[] data, ClientInfo client)
    {
        Log($"  [READY] Client {client.ClientId} is ready!");
        client.State = ClientState.InGame;

        // Send StartGame
        var startGame = new byte[5];
        startGame[0] = (byte)GamePacketId.StartGameS2C;

        _server.SendPacket(client, startGame, Channel.ServerToClient);
        Log($"  [GAME] Sent StartGame to client {client.ClientId}!");

        // Send initial game timer
        var gameTimer = new byte[9];
        gameTimer[0] = (byte)GamePacketId.GameTimerS2C;
        BitConverter.GetBytes(0.0f).CopyTo(gameTimer, 1);
        BitConverter.GetBytes(0.0f).CopyTo(gameTimer, 5);
        _server.SendPacket(client, gameTimer, Channel.Gameplay);

        // Start game loop if not already running
        if (_gameLoop == null)
        {
            _gameLoop = new GameLoop(_server, _config);
            _gameLoop.Initialize();

            // Spawn player champion
            var playerConfig = client.ClientId < _config.Players.Count
                ? _config.Players[client.ClientId]
                : _config.Players[0];

            var champion = _gameLoop.SpawnEntity(new Champion
            {
                ChampionName = playerConfig.Champion,
                SummonerName = playerConfig.Name,
                OwnerClientId = client.ClientId,
                Team = playerConfig.Team,
                SkinId = playerConfig.SkinId,
                Position = playerConfig.Team == TeamId.Blue
                    ? _gameLoop.Map.GetBlueSpawn()
                    : _gameLoop.Map.GetRedSpawn(),
                SpawnPosition = playerConfig.Team == TeamId.Blue
                    ? _gameLoop.Map.GetBlueSpawn()
                    : _gameLoop.Map.GetRedSpawn(),
                SummonerSpell1 = playerConfig.SummonerSpell1,
                SummonerSpell2 = playerConfig.SummonerSpell2,
            });

            Log($"  [SPAWN] Champion {champion.ChampionName} spawned for {champion.SummonerName}");

            // Start game loop on a separate thread
            _gameThread = new Thread(() => _gameLoop.StartGame())
            {
                IsBackground = true,
                Name = "GameLoop"
            };
            _gameThread.Start();
            Log($"  [GAME] Game loop started on background thread!");
        }
    }

    private void HandleRequestJoinTeam(byte[] data, ClientInfo client)
    {
        Log($"  [JOIN] Client {client.ClientId} requesting to join team");

        // Get player config
        int playerIdx = client.ClientId;
        PlayerConfig? playerConfig = playerIdx < _config.Players.Count
            ? _config.Players[playerIdx]
            : null;

        if (playerConfig != null)
        {
            client.Name = playerConfig.Name;
            client.Champion = playerConfig.Champion;
            client.SkinId = playerConfig.SkinId;
        }

        // Send TeamRosterUpdate
        var roster = new byte[64];
        roster[0] = (byte)LoadScreenPacketId.TeamRosterUpdate;
        // Team data - simplified
        BitConverter.GetBytes((uint)(playerConfig?.Team ?? TeamId.Blue)).CopyTo(roster, 1);
        BitConverter.GetBytes(client.ClientId).CopyTo(roster, 5);

        _server.SendPacket(client, roster, Channel.LoadingScreen);

        // Send PlayerNameUpdate
        var namePacket = new byte[128];
        namePacket[0] = (byte)LoadScreenPacketId.PlayerNameUpdate;
        BitConverter.GetBytes(client.ClientId).CopyTo(namePacket, 1);
        var nameBytes = Encoding.UTF8.GetBytes(client.Name);
        Array.Copy(nameBytes, 0, namePacket, 5, Math.Min(nameBytes.Length, 122));

        _server.SendPacket(client, namePacket, Channel.LoadingScreen);

        // Send PlayerChampionUpdate
        var champPacket = new byte[128];
        champPacket[0] = (byte)LoadScreenPacketId.PlayerChampionUpdate;
        BitConverter.GetBytes(client.ClientId).CopyTo(champPacket, 1);
        var champBytes = Encoding.UTF8.GetBytes(client.Champion);
        Array.Copy(champBytes, 0, champPacket, 5, Math.Min(champBytes.Length, 122));

        _server.SendPacket(client, champPacket, Channel.LoadingScreen);

        Log($"  [JOIN] Sent roster + name ({client.Name}) + champion ({client.Champion}) to client");
    }

    private void HandleRequestReskin(byte[] data, ClientInfo client)
    {
        Log($"  [RESKIN] Client {client.ClientId} requesting reskin");
        // Echo back confirmation
    }

    private void HandleRequestRename(byte[] data, ClientInfo client)
    {
        Log($"  [RENAME] Client {client.ClientId} requesting rename");
        // Echo back confirmation
    }

    private void Log(string message)
    {
        var timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
        Console.WriteLine($"[{timestamp}] {message}");
    }

    private void LogHex(byte[] data, int maxBytes = 48)
    {
        var hex = BitConverter.ToString(data, 0, Math.Min(maxBytes, data.Length));
        var truncated = data.Length > maxBytes ? $"... ({data.Length} total)" : "";
        Log($"    Hex: {hex}{truncated}");
    }
}
