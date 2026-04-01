using System;
using System.Linq;
using System.Text;
using System.Threading;
using LoLServer.Core.Config;
using LoLServer.Core.Game;
using LoLServer.Core.Game.Entities;
using LoLServer.Core.Game.Items;
using LoLServer.Core.Game.Spells;
using LoLServer.Core.Protocol;
using LoLServer.Core.Protocol.Packets;

namespace LoLServer.Core.Network;

/// <summary>
/// Routes decrypted packets to the appropriate handler based on channel and opcode.
/// Implements the full handshake → loading → spawn → game sequence.
/// </summary>
public class PacketHandler
{
    private readonly GameConfig _config;
    private readonly IGameServer _server;
    private GameLoop? _gameLoop;
    private Thread? _gameThread;
    private bool _gameStarted;

    public PacketHandler(GameConfig config, IGameServer server)
    {
        _config = config;
        _server = server;
    }

    public GameLoop? GameLoop => _gameLoop;

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

    // ======= Channel Routing =======

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

            case GamePacketId.MovementRequestC2S:
                HandleMovementRequest(data, client);
                break;

            case GamePacketId.StopMovementC2S:
                HandleStopMovement(data, client);
                break;

            case GamePacketId.AutoAttackC2S:
                HandleAutoAttack(data, client);
                break;

            case GamePacketId.StopAutoAttackC2S:
                HandleStopAutoAttack(data, client);
                break;

            case GamePacketId.CastSpellC2S:
                HandleCastSpell(data, client);
                break;

            case GamePacketId.CastSummonerSpellC2S:
                HandleCastSummonerSpell(data, client);
                break;

            case GamePacketId.LevelUpSpellC2S:
                HandleLevelUpSpell(data, client);
                break;

            case GamePacketId.BuyItemC2S:
                HandleBuyItem(data, client);
                break;

            case GamePacketId.SellItemC2S:
                HandleSellItem(data, client);
                break;

            case GamePacketId.SwapItemC2S:
                HandleSwapItem(data, client);
                break;

            case GamePacketId.EmotionC2S:
                HandleEmote(data, client);
                break;

            case GamePacketId.PingC2S:
                HandlePing(data, client);
                break;

            case GamePacketId.SyncClockC2S:
                HandleSyncClock(data, client);
                break;

            case GamePacketId.RecallC2S:
                HandleRecall(data, client);
                break;

            case GamePacketId.SurrenderVoteC2S:
                HandleSurrenderVote(data, client);
                break;

            default:
                Log($"  [C2S] Unknown opcode 0x{opcode:X2}");
                LogHex(data);
                break;
        }
    }

    private void HandleGameplay(byte opcode, byte[] data, ClientInfo client)
    {
        switch ((GamePacketId)opcode)
        {
            case GamePacketId.SyncClockC2S:
                HandleSyncClock(data, client);
                break;

            default:
                Log($"  [GAMEPLAY] Opcode=0x{opcode:X2} Len={data.Length}");
                LogHex(data);
                break;
        }
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
        if (data.Length < 7)
        {
            Log($"  [CHAT] Too short from client {client.ClientId}");
            return;
        }

        byte chatType = data[5]; // 0 = /all, 1 = /team
        string message;
        try
        {
            message = Encoding.UTF8.GetString(data, 6, data.Length - 6).TrimEnd('\0');
        }
        catch
        {
            Log($"  [CHAT] Invalid UTF8 from client {client.ClientId}");
            return;
        }

        string senderName = client.SummonerName ?? $"Player{client.ClientId}";
        bool isAllChat = chatType == 0;

        Log($"  [CHAT] [{(isAllChat ? "ALL" : "TEAM")}] {senderName}: {message}");

        // Build chat response packet
        var nameBytes = Encoding.UTF8.GetBytes(senderName);
        var msgBytes = Encoding.UTF8.GetBytes(message);
        var response = new byte[1 + 4 + 1 + nameBytes.Length + 1 + msgBytes.Length + 1];
        response[0] = (byte)GamePacketId.ChatMessageS2C;
        BitConverter.GetBytes(client.ChampionNetId).CopyTo(response, 1);
        response[5] = chatType;
        Array.Copy(nameBytes, 0, response, 6, nameBytes.Length);
        response[6 + nameBytes.Length] = 0;
        Array.Copy(msgBytes, 0, response, 7 + nameBytes.Length, msgBytes.Length);
        response[response.Length - 1] = 0;

        if (isAllChat)
            _server.BroadcastPacket(response, Channel.Communication);
        else
            _server.BroadcastPacketToTeam(response, Channel.Communication, client.Team);
    }

    // ======= Handshake / Loading Handlers =======

    private void HandleSynchVersion(byte[] data, ClientInfo client)
    {
        Log($"  [SYNCH] Client requests version sync");

        // Parse client version string if present
        if (data.Length > 5)
        {
            try
            {
                var clientVersion = Encoding.ASCII.GetString(data, 5, Math.Min(128, data.Length - 5)).TrimEnd('\0');
                if (!string.IsNullOrWhiteSpace(clientVersion))
                    Log($"  [SYNCH] Client version: '{clientVersion}'");
            }
            catch { }
        }

        var response = new byte[512];
        response[0] = (byte)GamePacketId.SynchVersionS2C;
        BitConverter.GetBytes(1u).CopyTo(response, 1); // Version OK
        var versionBytes = Encoding.ASCII.GetBytes(_config.GameVersion);
        Array.Copy(versionBytes, 0, response, 5, Math.Min(versionBytes.Length, 127));
        BitConverter.GetBytes(_config.MapId).CopyTo(response, 133);
        BitConverter.GetBytes(_config.Players.Count).CopyTo(response, 137);

        _server.SendPacket(client, response, Channel.ServerToClient);
        Log($"  [SYNCH] Sent SynchVersionS2C (version={_config.GameVersion}, map={_config.MapId})");
    }

    private void HandlePingLoadInfo(byte[] data, ClientInfo client)
    {
        if (data.Length >= 5)
        {
            var progress = BitConverter.ToSingle(data, 1);
            client.LoadingProgress = progress;
            Log($"  [LOAD] Client {client.ClientId} loading: {progress:P0}");

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

        // Initialize game world if not done yet
        EnsureGameInitialized();

        // === FULL SPAWN SEQUENCE ===

        // 1. StartSpawn
        _server.SendPacket(client,
            PacketWriter.Create(GamePacketId.StartSpawnS2C).WriteByte(0).ToArray(),
            Channel.ServerToClient);

        // 2. Spawn all turrets
        foreach (var entity in _gameLoop!.Entities)
        {
            if (entity is Turret turret)
            {
                _server.SendPacket(client, GamePackets.CreateTurret(turret), Channel.ServerToClient);
            }
        }
        Log($"  [SPAWN] Sent turret spawns to client {client.ClientId}");

        // 3. Spawn all existing champions
        int playerNo = 0;
        foreach (var entity in _gameLoop.Entities)
        {
            if (entity is Champion champ)
            {
                _server.SendPacket(client, GamePackets.CreateHero(champ, playerNo), Channel.ServerToClient);
                playerNo++;
            }
        }

        // 4. EndSpawn
        _server.SendPacket(client,
            PacketWriter.Create(GamePacketId.EndSpawnS2C).WriteByte(0).ToArray(),
            Channel.ServerToClient);

        Log($"  [SPAWN] Full spawn sequence sent to client {client.ClientId}");
    }

    private void HandleClientReady(byte[] data, ClientInfo client)
    {
        Log($"  [READY] Client {client.ClientId} is ready!");
        client.State = ClientState.InGame;

        EnsureGameInitialized();

        // Send StartGame
        var startGame = PacketWriter.Create(GamePacketId.StartGameS2C)
            .WriteUInt32(0)
            .ToArray();
        _server.SendPacket(client, startGame, Channel.ServerToClient);

        // Send game timer
        var gameTimer = PacketWriter.Create(GamePacketId.GameTimerS2C)
            .WriteFloat(_gameLoop!.GameTime)
            .WriteFloat(_gameLoop.GameTime)
            .ToArray();
        _server.SendPacket(client, gameTimer, Channel.Gameplay);

        // Spawn player's champion if not already spawned
        var existingChamp = _gameLoop.Champions.FirstOrDefault(c => c.OwnerClientId == client.ClientId);
        if (existingChamp == null)
        {
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

            client.ChampionNetId = champion.Id;
            client.SummonerName = playerConfig.Name;
            client.Champion = playerConfig.Champion;
            client.Team = playerConfig.Team;

            Log($"  [SPAWN] Champion {champion.ChampionName} (NetId=0x{champion.Id:X8}) spawned for {champion.SummonerName}");

            // Broadcast CreateHero to all clients
            int playerNo = _gameLoop.Champions.Count - 1;
            _server.BroadcastPacket(GamePackets.CreateHero(champion, playerNo), Channel.ServerToClient);

            // Send initial stats
            _server.SendPacket(client, GamePackets.StatsUpdate(champion), Channel.ServerToClient);
            _server.SendPacket(client, GamePackets.GoldUpdate(champion.Id, champion.Gold), Channel.ServerToClient);
            _server.SendPacket(client, GamePackets.InventoryUpdate(champion.Id, champion.Items), Channel.ServerToClient);
        }

        // Send welcome announcement
        _server.SendPacket(client,
            GamePackets.Announce(AnnounceEvent.Welcome, client.ChampionNetId),
            Channel.ServerToClient);

        // Start game loop if not already running
        if (!_gameStarted)
        {
            _gameStarted = true;
            _gameThread = new Thread(() => _gameLoop.StartGame())
            {
                IsBackground = true,
                Name = "GameLoop"
            };
            _gameThread.Start();
            Log($"  [GAME] Game loop started on background thread!");
        }

        Log($"  [GAME] Client {client.ClientId} is IN GAME!");
    }

    // ======= Movement Handlers =======

    private void HandleMovementRequest(byte[] data, ClientInfo client)
    {
        // Format: [1B opcode] [4B netId?] [1B moveType] [4B x] [4B y] [4B z]
        if (data.Length < 14) return;

        var reader = new PacketReader(data);
        reader.Skip(1); // opcode
        reader.Skip(4); // netId or padding
        var moveType = reader.ReadByte();
        var x = reader.ReadFloat();

        // Some clients send 2D (x,z), some send 3D
        float y = 0;
        float z;
        if (reader.Remaining >= 8)
        {
            y = reader.ReadFloat();
            z = reader.ReadFloat();
        }
        else if (reader.Remaining >= 4)
        {
            z = reader.ReadFloat();
        }
        else
        {
            z = x;
            x = BitConverter.ToSingle(data, 6);
        }

        var champion = GetChampion(client);
        if (champion == null) return;

        champion.MoveTarget = new Vector3(x, y, z);
        Log($"  [MOVE] {client.SummonerName} moving to ({x:F0}, {z:F0})");

        // Broadcast movement to all clients
        _server.BroadcastPacket(
            GamePackets.Movement(client.ChampionNetId, x, y, z, champion.MoveSpeed),
            Channel.ServerToClient);
    }

    private void HandleStopMovement(byte[] data, ClientInfo client)
    {
        var champion = GetChampion(client);
        if (champion == null) return;

        champion.MoveTarget = null;

        _server.BroadcastPacket(
            GamePackets.Movement(client.ChampionNetId,
                champion.Position.X, champion.Position.Y, champion.Position.Z,
                0, MovementType.Stop),
            Channel.ServerToClient);
    }

    // ======= Combat Handlers =======

    private void HandleAutoAttack(byte[] data, ClientInfo client)
    {
        // Format: [1B opcode] [4B targetNetId]
        if (data.Length < 5) return;

        var targetNetId = BitConverter.ToUInt32(data, 1);
        var champion = GetChampion(client);
        if (champion == null || _gameLoop == null) return;

        var target = _gameLoop.GetEntity(targetNetId);
        if (target == null) return;

        Log($"  [ATTACK] {client.SummonerName} auto-attacking {target.Name} (0x{targetNetId:X8})");

        // Move to attack range then attack
        var dist = champion.Position.Distance2D(target.Position);
        if (dist > champion.AttackRange)
        {
            champion.MoveTarget = target.Position;
            _server.BroadcastPacket(
                GamePackets.Movement(client.ChampionNetId,
                    target.Position.X, target.Position.Y, target.Position.Z,
                    champion.MoveSpeed),
                Channel.ServerToClient);
        }

        // Notify clients of attack target
        _server.BroadcastPacket(
            PacketWriter.CreateWithSender(GamePacketId.AttackTargetS2C, client.ChampionNetId)
                .WriteUInt32(targetNetId)
                .ToArray(),
            Channel.ServerToClient);
    }

    private void HandleStopAutoAttack(byte[] data, ClientInfo client)
    {
        Log($"  [ATTACK] {client.SummonerName} stopped auto-attacking");
    }

    // ======= Ability Handlers =======

    private void HandleCastSpell(byte[] data, ClientInfo client)
    {
        // Format: [1B opcode] [1B slot] [4B x] [4B y] [4B z] [4B targetNetId]
        if (data.Length < 6) return;

        var reader = new PacketReader(data);
        reader.Skip(1); // opcode
        var slot = reader.ReadByte();
        float x = 0, y = 0, z = 0;
        uint targetNetId = 0;

        if (reader.Remaining >= 12)
        {
            x = reader.ReadFloat();
            y = reader.ReadFloat();
            z = reader.ReadFloat();
        }
        if (reader.Remaining >= 4)
        {
            targetNetId = reader.ReadUInt32();
        }

        var champion = GetChampion(client);
        if (champion == null || _gameLoop == null) return;

        if (slot >= 4)
        {
            Log($"  [SPELL] {client.SummonerName} invalid spell slot {slot}");
            return;
        }

        var ability = champion.Abilities[slot];
        Log($"  [SPELL] {client.SummonerName} cast spell slot {slot} at ({x:F0},{z:F0}) target=0x{targetNetId:X8}");

        // Use SpellManager to cast spell (handles damage, mana, cooldown)
        var targetEntity = targetNetId != 0 ? _gameLoop.GetEntity(targetNetId) : null;
        var targetPos = new Vector3(x, y, z);
        var castResult = SpellManager.CastSpell(champion, slot, targetPos, targetEntity, _gameLoop);

        if (castResult.Success && targetEntity is IKillable killable)
        {
            _server.BroadcastPacket(
                GamePackets.SetHealth(targetNetId, killable.Health, killable.MaxHealth),
                Channel.ServerToClient);
        }

        // Broadcast spell cast
        _server.BroadcastPacket(
            GamePackets.CastSpell(client.ChampionNetId, (byte)slot, x, y, z, targetNetId),
            Channel.ServerToClient);

        // Send cooldown update
        _server.SendPacket(client,
            GamePackets.SetCooldown(client.ChampionNetId, (byte)slot, ability.CurrentCooldown, ability.Cooldown),
            Channel.ServerToClient);
    }

    private void HandleCastSummonerSpell(byte[] data, ClientInfo client)
    {
        // Format: [1B opcode] [1B slot (4=D, 5=F)] [4B x] [4B z] [4B targetNetId]
        if (data.Length < 2) return;

        var slot = data[1]; // 4 = D, 5 = F
        var champion = GetChampion(client);
        if (champion == null) return;

        var spellName = slot == 4 ? champion.SummonerSpell1 : champion.SummonerSpell2;
        Log($"  [SUMMONER] {client.SummonerName} cast {spellName} (slot {slot})");

        float x = 0, z = 0;
        uint targetNetId = 0;
        if (data.Length >= 10) { x = BitConverter.ToSingle(data, 2); z = BitConverter.ToSingle(data, 6); }
        if (data.Length >= 14) { targetNetId = BitConverter.ToUInt32(data, 10); }

        var targetEntity = targetNetId != 0 ? _gameLoop!.GetEntity(targetNetId) : null;
        SpellManager.CastSummonerSpell(champion, spellName, new Vector3(x, 0, z), targetEntity, _gameLoop!);
    }

    private void HandleLevelUpSpell(byte[] data, ClientInfo client)
    {
        // Format: [1B opcode] [1B slot]
        if (data.Length < 2) return;

        var slot = data[1];
        var champion = GetChampion(client);
        if (champion == null || slot >= 4) return;

        var ability = champion.Abilities[slot];
        if (ability.Level >= 5 || (slot == 3 && ability.Level >= 3)) return;

        ability.Level++;
        Log($"  [LEVEL] {client.SummonerName} leveled up spell slot {slot} to level {ability.Level}");

        _server.BroadcastPacket(
            GamePackets.LevelUpSpell(client.ChampionNetId, (byte)slot, (byte)ability.Level),
            Channel.ServerToClient);
    }

    // ======= Item Handlers =======

    private void HandleBuyItem(byte[] data, ClientInfo client)
    {
        // Format: [1B opcode] [4B itemId]
        if (data.Length < 5) return;

        var itemId = BitConverter.ToInt32(data, 1);
        var champion = GetChampion(client);
        if (champion == null) return;

        Log($"  [ITEM] {client.SummonerName} wants to buy item {itemId}");

        var buyResult = ItemManager.TryBuyItem(champion, itemId);
        if (buyResult.Success)
        {
            // Find slot
            int slot = -1;
            for (int i = 0; i < 6; i++)
            {
                if (champion.Items[i] == itemId) { slot = i; break; }
            }

            Log($"  [ITEM] {client.SummonerName} bought item {itemId} in slot {slot}");

            _server.BroadcastPacket(
                GamePackets.ItemBuy(client.ChampionNetId, itemId, slot, 1),
                Channel.ServerToClient);
            _server.SendPacket(client,
                GamePackets.GoldUpdate(client.ChampionNetId, champion.Gold),
                Channel.ServerToClient);
            _server.SendPacket(client,
                GamePackets.StatsUpdate(champion),
                Channel.ServerToClient);
        }
        else
        {
            Log($"  [ITEM] {client.SummonerName} cannot buy item {itemId} (no gold or no slot)");
        }
    }

    private void HandleSellItem(byte[] data, ClientInfo client)
    {
        // Format: [1B opcode] [1B slot]
        if (data.Length < 2) return;

        var slot = data[1];
        var champion = GetChampion(client);
        if (champion == null || slot >= 6) return;

        var itemId = champion.Items[slot];
        if (itemId == 0) return;

        ItemManager.SellItem(champion, slot);
        Log($"  [ITEM] {client.SummonerName} sold item {itemId} from slot {slot}");

        _server.SendPacket(client,
            GamePackets.InventoryUpdate(client.ChampionNetId, champion.Items),
            Channel.ServerToClient);
        _server.SendPacket(client,
            GamePackets.GoldUpdate(client.ChampionNetId, champion.Gold),
            Channel.ServerToClient);
        _server.SendPacket(client,
            GamePackets.StatsUpdate(champion),
            Channel.ServerToClient);
    }

    private void HandleSwapItem(byte[] data, ClientInfo client)
    {
        if (data.Length < 3) return;
        var slotA = data[1];
        var slotB = data[2];
        var champion = GetChampion(client);
        if (champion == null || slotA >= 6 || slotB >= 6) return;

        (champion.Items[slotA], champion.Items[slotB]) = (champion.Items[slotB], champion.Items[slotA]);

        _server.SendPacket(client,
            GamePackets.InventoryUpdate(client.ChampionNetId, champion.Items),
            Channel.ServerToClient);
    }

    // ======= Misc Handlers =======

    private void HandleEmote(byte[] data, ClientInfo client)
    {
        if (data.Length < 2) return;
        var emoteId = data[1];
        Log($"  [EMOTE] {client.SummonerName} emote {emoteId}");
        // Broadcast emote to nearby clients
    }

    private void HandlePing(byte[] data, ClientInfo client)
    {
        // Format: [1B opcode] [4B x] [4B y] [1B pingType]
        if (data.Length < 10) return;

        var x = BitConverter.ToSingle(data, 1);
        var y = BitConverter.ToSingle(data, 5);
        var pingType = data[9];

        Log($"  [PING] {client.SummonerName} ping type={pingType} at ({x:F0},{y:F0})");

        // Broadcast to team
        _server.BroadcastPacketToTeam(
            GamePackets.Ping(client.ChampionNetId, x, y, pingType),
            Channel.ServerToClient,
            client.Team);
    }

    private void HandleSyncClock(byte[] data, ClientInfo client)
    {
        if (data.Length < 5) return;
        var clientSyncId = BitConverter.ToUInt32(data, 1);
        float gameTime = _gameLoop?.GameTime ?? 0;

        _server.SendPacket(client,
            GamePackets.SyncClock(gameTime, clientSyncId),
            Channel.Gameplay);
    }

    private void HandleRecall(byte[] data, ClientInfo client)
    {
        Log($"  [RECALL] {client.SummonerName} started recalling");
        // TODO: Start 8s recall timer, teleport to spawn on completion
    }

    private void HandleSurrenderVote(byte[] data, ClientInfo client)
    {
        if (data.Length < 2) return;
        bool yesVote = data[1] != 0;
        Log($"  [SURRENDER] {client.SummonerName} voted {(yesVote ? "YES" : "NO")}");
        // TODO: Track votes, trigger surrender at 4/5 or 5/5
    }

    // ======= Loading Screen Handlers =======

    private void HandleRequestJoinTeam(byte[] data, ClientInfo client)
    {
        Log($"  [JOIN] Client {client.ClientId} requesting to join team");

        int playerIdx = client.ClientId;
        PlayerConfig? playerConfig = playerIdx < _config.Players.Count
            ? _config.Players[playerIdx]
            : null;

        if (playerConfig != null)
        {
            client.Name = playerConfig.Name;
            client.SummonerName = playerConfig.Name;
            client.Champion = playerConfig.Champion;
            client.SkinId = playerConfig.SkinId;
            client.Team = playerConfig.Team;
        }

        // Send TeamRosterUpdate
        var roster = new byte[64];
        roster[0] = (byte)LoadScreenPacketId.TeamRosterUpdate;
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
    }

    private void HandleRequestRename(byte[] data, ClientInfo client)
    {
        Log($"  [RENAME] Client {client.ClientId} requesting rename");
    }

    // ======= Helpers =======

    private Champion? GetChampion(ClientInfo client)
    {
        if (_gameLoop == null || client.ChampionNetId == 0) return null;
        return _gameLoop.GetEntity(client.ChampionNetId) as Champion;
    }

    private void EnsureGameInitialized()
    {
        if (_gameLoop == null)
        {
            _gameLoop = new GameLoop(_server, _config);
            _gameLoop.Initialize();
            Log($"  [GAME] Game world initialized");
        }
    }

    private void Log(string message)
    {
        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] {message}");
    }

    private void LogHex(byte[] data, int maxBytes = 48)
    {
        var hex = BitConverter.ToString(data, 0, Math.Min(maxBytes, data.Length));
        var truncated = data.Length > maxBytes ? $"... ({data.Length} total)" : "";
        Log($"    Hex: {hex}{truncated}");
    }
}
