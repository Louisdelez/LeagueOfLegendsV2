using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using LoLServer.Core.Config;
using LoLServer.Core.Game.Entities;
using LoLServer.Core.Game.Items;
using LoLServer.Core.Game.Jungle;
using LoLServer.Core.Game.Map;
using LoLServer.Core.Game.Vision;
using LoLServer.Core.Network;
using LoLServer.Core.Protocol;
using LoLServer.Core.Protocol.Packets;

namespace LoLServer.Core.Game;

/// <summary>
/// Main game loop running at 30 Hz (33.33ms per tick).
/// Handles game state updates, entity spawning, combat, and syncing with clients.
/// </summary>
public class GameLoop
{
    public const float TickRate = 30.0f;
    public const float TickInterval = 1.0f / TickRate;

    private readonly IGameServer _server;
    private readonly GameConfig _config;
    private readonly MapManager _map;
    private readonly List<GameEntity> _entities = new();
    private readonly Dictionary<uint, GameEntity> _entityById = new();
    private readonly List<Champion> _champions = new();

    private JungleManager? _jungle;
    private VisionSystem? _vision;

    private float _gameTime;
    private float _nextMinionSpawnTime;
    private uint _nextEntityId = 0x40000001;
    private bool _running;

    // Timers
    private const float FirstMinionSpawnTime = 65.0f;
    private const float MinionSpawnInterval = 30.0f;
    private const float PassiveGoldRate = 2.04f;      // Gold per second after 2:00
    private const float PassiveGoldStart = 120.0f;     // 2:00
    private const float XpShareRange = 1600.0f;        // XP share radius

    // Game state
    private int _blueKills;
    private int _redKills;
    private int _blueDragons;
    private int _redDragons;
    private bool _baronAlive;
    private readonly List<Minion> _pendingMinionSpawns = new();

    public float GameTime => _gameTime;
    public MapManager Map => _map;
    public VisionSystem? Vision => _vision;
    public IReadOnlyList<GameEntity> Entities => _entities;
    public IReadOnlyList<Champion> Champions => _champions;

    public GameLoop(IGameServer server, GameConfig config)
    {
        _server = server;
        _config = config;
        _map = new MapManager(config.MapId);
        _nextMinionSpawnTime = FirstMinionSpawnTime;
    }

    public uint AllocateEntityId() => _nextEntityId++;

    public T SpawnEntity<T>(T entity) where T : GameEntity
    {
        entity.Id = AllocateEntityId();
        _entities.Add(entity);
        _entityById[entity.Id] = entity;
        if (entity is Champion champ)
            _champions.Add(champ);
        if (entity is Minion minion)
            _pendingMinionSpawns.Add(minion);
        return entity;
    }

    public void RemoveEntity(uint entityId)
    {
        if (_entityById.TryGetValue(entityId, out var entity))
        {
            _entities.Remove(entity);
            _entityById.Remove(entityId);
            if (entity is Champion champ)
                _champions.Remove(champ);
        }
    }

    public GameEntity? GetEntity(uint id) => _entityById.TryGetValue(id, out var e) ? e : null;

    public void Initialize()
    {
        Log("[GAME] Initializing game world...");

        // Spawn turrets
        foreach (var t in _map.GetTurrets())
        {
            SpawnEntity(new Turret
            {
                Name = t.Name, Team = t.Team, Position = t.Position,
                MaxHealth = t.Health, Health = t.Health,
                AttackDamage = t.Damage, AttackRange = t.Range, IsTargetable = true
            });
        }
        Log($"  {_map.GetTurrets().Count} turrets spawned");

        // Spawn inhibitors
        foreach (var inh in _map.GetInhibitors())
        {
            SpawnEntity(new Inhibitor
            {
                Name = inh.Name, Team = inh.Team, Position = inh.Position,
                MaxHealth = 4000, Health = 4000, IsTargetable = true
            });
        }
        Log($"  {_map.GetInhibitors().Count} inhibitors spawned");

        // Spawn nexus
        foreach (var n in _map.GetNexusPositions())
        {
            SpawnEntity(new Nexus
            {
                Name = n.Name, Team = n.Team, Position = n.Position,
                MaxHealth = 5500, Health = 5500, IsTargetable = true
            });
        }
        Log($"  {_map.GetNexusPositions().Count} nexus spawned");

        // Initialize jungle (SR only)
        if (_config.MapId == 11)
        {
            _jungle = new JungleManager(this);
            Log($"  {_jungle.Camps.Count} jungle camps registered");
        }

        // Initialize vision system
        _vision = new VisionSystem(this);
        Log($"  Vision system initialized");

        Log($"[GAME] World initialized: {_entities.Count} entities on Map {_config.MapId}");
    }

    public void StartGame()
    {
        _running = true;
        _gameTime = 0;
        Log("[GAME] === GAME STARTED ===");

        var stopwatch = Stopwatch.StartNew();
        var tickDuration = TimeSpan.FromSeconds(TickInterval);
        long tickCount = 0;

        while (_running)
        {
            var tickStart = stopwatch.Elapsed;

            Update(TickInterval);
            tickCount++;

            // Periodic broadcasts
            if (tickCount % 30 == 0)  // Every 1s
            {
                SendGameTimer();
                BroadcastChampionStats();

                if (tickCount % 150 == 0) // Every 5s
                    BroadcastScoreboard();

                if (tickCount % 300 == 0) // Every 10s
                    LogGameState();
            }

            // Broadcast minion spawns (newly created minions)
            if (tickCount % 30 == 0)
                BroadcastNewMinions();

            var elapsed = stopwatch.Elapsed - tickStart;
            var sleepTime = tickDuration - elapsed;
            if (sleepTime > TimeSpan.Zero)
                Thread.Sleep(sleepTime);
        }
    }

    private void Update(float dt)
    {
        _gameTime += dt;

        // Passive gold
        if (_gameTime >= PassiveGoldStart)
        {
            foreach (var champ in _champions)
            {
                if (!champ.IsDead)
                    champ.Gold += PassiveGoldRate * dt;
            }
        }

        // Spawn minions
        if (_gameTime >= _nextMinionSpawnTime)
        {
            SpawnMinionWave();
            _nextMinionSpawnTime += MinionSpawnInterval;
        }

        // Update jungle
        _jungle?.Update(dt);

        // Update vision
        _vision?.Update(dt);

        // Update all entities
        for (int i = _entities.Count - 1; i >= 0; i--)
        {
            _entities[i].Update(dt, this);
        }

        // Process per-tick item passives for champions
        foreach (var champ in _champions)
        {
            if (!champ.IsDead)
                ItemPassiveManager.ProcessPerTick(champ, dt, this);
        }

        // Process deaths
        for (int i = _entities.Count - 1; i >= 0; i--)
        {
            var entity = _entities[i];
            if (entity is IKillable killable && killable.Health <= 0 && !entity.MarkedForRemoval)
            {
                entity.MarkedForRemoval = true;
                OnEntityDeath(entity);
            }
        }

        // Clean dead entities (except champions who respawn)
        _entities.RemoveAll(e => e.MarkedForRemoval && e is not Champion);

        // Reset MarkedForRemoval on dead champions (they stay in list for respawn)
        foreach (var champ in _champions)
        {
            if (champ.MarkedForRemoval && champ.IsDead)
                champ.MarkedForRemoval = false;
        }

        // Broadcast respawns
        foreach (var champ in _champions)
        {
            if (champ.JustRespawned)
            {
                champ.JustRespawned = false;
                _server.BroadcastPacket(
                    GamePackets.NpcRespawn(champ.Id, champ.Position.X, champ.Position.Y, champ.Position.Z),
                    Channel.ServerToClient);
                _server.BroadcastPacket(
                    GamePackets.SetHealth(champ.Id, champ.Health, champ.MaxHealth),
                    Channel.ServerToClient);
                Log($"[RESPAWN] {champ.SummonerName} respawned!");
            }
        }

        // Check win condition
        CheckWinCondition();
    }

    private void OnEntityDeath(GameEntity entity)
    {
        // Find killer (nearest enemy champion)
        Champion? killer = FindNearestEnemyChampion(entity);

        switch (entity)
        {
            case Champion deadChamp:
                deadChamp.Die(killer);
                if (deadChamp.Team == TeamId.Blue) _redKills++;
                else _blueKills++;

                // Share XP with nearby allies
                float deathXp = 100 + deadChamp.Level * 20;
                ShareXpWithNearbyAllies(entity.Position, killer?.Team ?? TeamId.Blue, deathXp);

                Log($"[KILL] {killer?.SummonerName ?? "?"} killed {deadChamp.SummonerName}! ({_blueKills}-{_redKills})");

                // Broadcast death
                _server.BroadcastPacket(
                    GamePackets.NpcDie(deadChamp.Id, killer?.Id ?? 0),
                    Channel.ServerToClient);
                _server.BroadcastPacket(
                    GamePackets.Announce(AnnounceEvent.ChampionKill, deadChamp.Id, killer?.Id ?? 0),
                    Channel.ServerToClient);
                break;

            case Minion minion:
                if (killer != null)
                {
                    killer.Gold += minion.GoldReward;
                    killer.AddExperience(minion.XpReward);
                    killer.CreepScore++;
                }
                else
                {
                    // Share XP even without last hit
                    ShareXpWithNearbyAllies(entity.Position,
                        entity.Team == TeamId.Blue ? TeamId.Red : TeamId.Blue, minion.XpReward);
                }
                break;

            case Turret turret:
                // Global gold for team
                float turretGold = 250;
                foreach (var champ in _champions.Where(c => c.Team != turret.Team))
                    champ.Gold += turretGold / _champions.Count(c => c.Team != turret.Team);
                Log($"[TURRET] {turret.Name} destroyed!");
                _server.BroadcastPacket(
                    GamePackets.NpcDie(turret.Id, killer?.Id ?? 0),
                    Channel.ServerToClient);
                _server.BroadcastPacket(
                    GamePackets.Announce(AnnounceEvent.TurretDestroyed, turret.Id),
                    Channel.ServerToClient);
                break;

            case Inhibitor inhib:
                Log($"[INHIBITOR] {inhib.Name} destroyed! Super minions incoming!");
                break;

            case Nexus nexus:
                var winTeam = nexus.Team == TeamId.Blue ? TeamId.Red : TeamId.Blue;
                Log($"[VICTORY] {winTeam} team wins! GG!");
                break;
        }
    }

    private void ShareXpWithNearbyAllies(Vector3 position, TeamId team, float totalXp)
    {
        var nearby = _champions
            .Where(c => c.Team == team && !c.IsDead && c.Position.Distance2D(position) <= XpShareRange)
            .ToList();

        if (nearby.Count == 0) return;

        float xpPerChamp = totalXp / nearby.Count;
        foreach (var champ in nearby)
            champ.AddExperience(xpPerChamp);
    }

    private Champion? FindNearestEnemyChampion(GameEntity deadEntity)
    {
        return _champions
            .Where(c => c.Team != deadEntity.Team && !c.IsDead)
            .OrderBy(c => c.Position.Distance2D(deadEntity.Position))
            .FirstOrDefault();
    }

    private void CheckWinCondition()
    {
        foreach (var entity in _entities)
        {
            if (entity is Nexus nexus && nexus.Health <= 0)
            {
                var winTeam = nexus.Team == TeamId.Blue ? "RED" : "BLUE";
                Log($"");
                Log($"  ========================================");
                Log($"  === {winTeam} TEAM VICTORY ===");
                Log($"  === Score: {_blueKills} - {_redKills} ===");
                Log($"  === Game Time: {_gameTime / 60:F0}:{_gameTime % 60:00} ===");
                Log($"  ========================================");
                Log($"");
                Stop();
            }
        }
    }

    private void SpawnMinionWave()
    {
        int waveNumber = (int)((_gameTime - FirstMinionSpawnTime) / MinionSpawnInterval);

        foreach (var lane in _map.GetLanes())
        {
            SpawnMinionWaveForTeam(lane, TeamId.Blue, waveNumber);
            SpawnMinionWaveForTeam(lane, TeamId.Red, waveNumber);
        }
    }

    private void SpawnMinionWaveForTeam(LaneData lane, TeamId team, int waveNumber)
    {
        var spawnPos = team == TeamId.Blue ? lane.BlueSpawn : lane.RedSpawn;
        var waypoints = team == TeamId.Blue ? lane.BlueWaypoints : lane.RedWaypoints;
        float offsetX = 0;

        // Scale minion stats over time
        float hpScale = 1 + (_gameTime / 60f) * 0.02f;
        float dmgScale = 1 + (_gameTime / 60f) * 0.015f;

        // 3 melee
        for (int i = 0; i < 3; i++)
        {
            SpawnEntity(new Minion
            {
                MinionType = MinionType.Melee, Team = team, Lane = lane.Name,
                Position = new Vector3(spawnPos.X + offsetX, spawnPos.Y, spawnPos.Z),
                MaxHealth = 477 * hpScale, Health = 477 * hpScale,
                AttackDamage = 12 * dmgScale, AttackRange = 110, MoveSpeed = 325,
                Waypoints = waypoints
            });
            offsetX += 50;
        }

        // 3 caster
        for (int i = 0; i < 3; i++)
        {
            SpawnEntity(new Minion
            {
                MinionType = MinionType.Caster, Team = team, Lane = lane.Name,
                Position = new Vector3(spawnPos.X + offsetX, spawnPos.Y, spawnPos.Z),
                MaxHealth = 296 * hpScale, Health = 296 * hpScale,
                AttackDamage = 23 * dmgScale, AttackRange = 600, MoveSpeed = 325,
                Waypoints = waypoints
            });
            offsetX += 50;
        }

        // Cannon (frequency increases over time)
        bool spawnCannon;
        if (_gameTime >= 25 * 60) spawnCannon = true;
        else if (_gameTime >= 15 * 60) spawnCannon = (waveNumber % 2 == 0);
        else spawnCannon = (waveNumber % 3 == 0);

        if (spawnCannon)
        {
            SpawnEntity(new Minion
            {
                MinionType = MinionType.Cannon, Team = team, Lane = lane.Name,
                Position = new Vector3(spawnPos.X + offsetX, spawnPos.Y, spawnPos.Z),
                MaxHealth = 828 * hpScale, Health = 828 * hpScale,
                AttackDamage = 40 * dmgScale, AttackRange = 600, MoveSpeed = 325,
                Waypoints = waypoints
            });
        }

        // Check for super minions (if enemy inhibitor destroyed)
        bool enemyInhibDestroyed = _entities
            .OfType<Inhibitor>()
            .Any(inh => inh.Team != team && inh.IsDestroyed && inh.Name.Contains(lane.Name.Substring(0, 1)));

        if (enemyInhibDestroyed)
        {
            SpawnEntity(new Minion
            {
                MinionType = MinionType.Super, Team = team, Lane = lane.Name,
                Position = new Vector3(spawnPos.X + offsetX + 50, spawnPos.Y, spawnPos.Z),
                MaxHealth = 1500 * hpScale, Health = 1500 * hpScale,
                AttackDamage = 40 * dmgScale, AttackRange = 170, MoveSpeed = 325,
                Waypoints = waypoints
            });
        }
    }

    private void SendGameTimer()
    {
        var packet = PacketWriter.Create(GamePacketId.GameTimerS2C)
            .WriteFloat(_gameTime)
            .WriteFloat(_gameTime)
            .ToArray();
        _server.BroadcastPacket(packet, Channel.Gameplay);
    }

    /// <summary>
    /// Broadcast HP/mana/stats for all champions to all clients (every 1s).
    /// </summary>
    private void BroadcastChampionStats()
    {
        foreach (var champ in _champions)
        {
            _server.BroadcastPacket(
                GamePackets.SetHealth(champ.Id, champ.Health, champ.MaxHealth),
                Channel.ServerToClient);
            _server.BroadcastPacket(
                GamePackets.GoldUpdate(champ.Id, champ.Gold),
                Channel.ServerToClient);
        }
    }

    /// <summary>
    /// Full stats + scoreboard sync (every 5s).
    /// </summary>
    private void BroadcastScoreboard()
    {
        foreach (var champ in _champions)
        {
            _server.BroadcastPacket(
                GamePackets.StatsUpdate(champ),
                Channel.ServerToClient);
            _server.BroadcastPacket(
                GamePackets.ScoreboardUpdate(champ),
                Channel.ServerToClient);
        }
    }

    /// <summary>
    /// Broadcast newly spawned minions to all clients, then clear the list.
    /// </summary>
    private void BroadcastNewMinions()
    {
        if (_pendingMinionSpawns.Count == 0) return;

        foreach (var minion in _pendingMinionSpawns)
        {
            _server.BroadcastPacket(
                GamePackets.CreateMinion(minion),
                Channel.ServerToClient);
        }

        if (_pendingMinionSpawns.Count > 0)
            Log($"[MINIONS] Broadcast {_pendingMinionSpawns.Count} new minion spawns");

        _pendingMinionSpawns.Clear();
    }

    private void LogGameState()
    {
        int minionCount = _entities.Count(e => e is Minion);
        int turretCount = _entities.Count(e => e is Turret t && t.Health > 0);
        Log($"[STATE] Time={_gameTime / 60:F0}:{_gameTime % 60:00} " +
            $"Score={_blueKills}-{_redKills} " +
            $"Entities={_entities.Count} Minions={minionCount} Turrets={turretCount} " +
            $"Champions={_champions.Count(c => !c.IsDead)}/{_champions.Count}");
    }

    public void Stop()
    {
        _running = false;
        Log("[GAME] Game loop stopped");
    }

    private void Log(string message)
    {
        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] {message}");
    }
}
