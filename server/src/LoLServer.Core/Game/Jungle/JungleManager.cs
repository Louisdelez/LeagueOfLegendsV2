using System;
using System.Collections.Generic;
using LoLServer.Core.Config;
using LoLServer.Core.Game.Entities;
using LoLServer.Core.Game.Spells;

namespace LoLServer.Core.Game.Jungle;

/// <summary>
/// Manages jungle camps, epic monsters (Dragon, Baron, Herald),
/// spawn timers, and rewards for Summoner's Rift.
/// </summary>
public class JungleManager
{
    private readonly List<JungleCamp> _camps = new();
    private readonly GameLoop _game;

    public IReadOnlyList<JungleCamp> Camps => _camps;

    public JungleManager(GameLoop game)
    {
        _game = game;

        if (game.Map.MapId == 11) // Summoner's Rift
        {
            InitializeSummonersRiftCamps();
        }
    }

    public void Update(float deltaTime)
    {
        foreach (var camp in _camps)
        {
            if (!camp.IsAlive)
            {
                camp.RespawnTimer -= deltaTime;
                if (camp.RespawnTimer <= 0)
                {
                    SpawnCamp(camp);
                }
            }
        }
    }

    public void OnCampKilled(JungleCamp camp, Champion killer)
    {
        camp.IsAlive = false;
        camp.RespawnTimer = camp.RespawnTime;

        // Grant gold and XP
        killer.Gold += camp.GoldReward;
        killer.AddExperience(camp.XpReward);

        Console.WriteLine($"[JUNGLE] {killer.SummonerName} killed {camp.Name} (+{camp.GoldReward}g, +{camp.XpReward}xp)");

        // Special effects for epic monsters
        switch (camp.Type)
        {
            case CampType.Dragon:
                Console.WriteLine($"[DRAGON] {killer.Team} team slayed Dragon!");
                break;
            case CampType.Baron:
                Console.WriteLine($"[BARON] {killer.Team} team slayed Baron Nashor! (Buff applied)");
                break;
            case CampType.Herald:
                Console.WriteLine($"[HERALD] {killer.Team} team defeated Rift Herald!");
                break;
        }
    }

    private void SpawnCamp(JungleCamp camp)
    {
        camp.IsAlive = true;

        // Spawn monsters for this camp
        foreach (var monsterData in camp.Monsters)
        {
            var monster = _game.SpawnEntity(new JungleMonster
            {
                Name = monsterData.Name,
                Team = TeamId.Blue, // Neutral
                Position = monsterData.Position,
                MaxHealth = monsterData.Health,
                Health = monsterData.Health,
                IsTargetable = true
            });
        }

        Console.WriteLine($"[JUNGLE] {camp.Name} spawned at {_game.GameTime:F0}s");
    }

    private void InitializeSummonersRiftCamps()
    {
        // === BLUE SIDE JUNGLE ===
        _camps.Add(new JungleCamp
        {
            Name = "Blue Sentinel (Blue)",
            Type = CampType.Buff,
            Side = TeamId.Blue,
            GoldReward = 100,
            XpReward = 110,
            RespawnTime = 300, // 5 min
            InitialSpawnTime = 90, // 1:30
            Monsters = new[]
            {
                new MonsterData("Blue Sentinel", new Vector3(3821, 0, 7901), 2100),
                new MonsterData("Sentry", new Vector3(3650, 0, 8050), 400),
                new MonsterData("Sentry", new Vector3(3950, 0, 8100), 400),
            }
        });

        _camps.Add(new JungleCamp
        {
            Name = "Gromp (Blue)",
            Type = CampType.Small,
            Side = TeamId.Blue,
            GoldReward = 80,
            XpReward = 135,
            RespawnTime = 135, // 2:15
            InitialSpawnTime = 102, // 1:42
            Monsters = new[]
            {
                new MonsterData("Gromp", new Vector3(2164, 0, 8383), 1800),
            }
        });

        _camps.Add(new JungleCamp
        {
            Name = "Wolves (Blue)",
            Type = CampType.Small,
            Side = TeamId.Blue,
            GoldReward = 68,
            XpReward = 95,
            RespawnTime = 135,
            InitialSpawnTime = 102,
            Monsters = new[]
            {
                new MonsterData("Greater Murk Wolf", new Vector3(3800, 0, 6491), 1600),
                new MonsterData("Murk Wolf", new Vector3(3650, 0, 6350), 480),
                new MonsterData("Murk Wolf", new Vector3(3950, 0, 6350), 480),
            }
        });

        _camps.Add(new JungleCamp
        {
            Name = "Raptors (Blue)",
            Type = CampType.Small,
            Side = TeamId.Blue,
            GoldReward = 85,
            XpReward = 95,
            RespawnTime = 135,
            InitialSpawnTime = 102,
            Monsters = new[]
            {
                new MonsterData("Crimson Raptor", new Vector3(6944, 0, 5413), 1100),
                new MonsterData("Raptor", new Vector3(6800, 0, 5250), 425),
                new MonsterData("Raptor", new Vector3(7050, 0, 5200), 425),
                new MonsterData("Raptor", new Vector3(6700, 0, 5500), 425),
                new MonsterData("Raptor", new Vector3(7100, 0, 5550), 425),
                new MonsterData("Raptor", new Vector3(6850, 0, 5650), 425),
            }
        });

        _camps.Add(new JungleCamp
        {
            Name = "Red Brambleback (Blue)",
            Type = CampType.Buff,
            Side = TeamId.Blue,
            GoldReward = 100,
            XpReward = 110,
            RespawnTime = 300,
            InitialSpawnTime = 90,
            Monsters = new[]
            {
                new MonsterData("Red Brambleback", new Vector3(7862, 0, 4112), 2100),
                new MonsterData("Cinderling", new Vector3(7700, 0, 3950), 400),
                new MonsterData("Cinderling", new Vector3(8050, 0, 4000), 400),
            }
        });

        _camps.Add(new JungleCamp
        {
            Name = "Krugs (Blue)",
            Type = CampType.Small,
            Side = TeamId.Blue,
            GoldReward = 96,
            XpReward = 128,
            RespawnTime = 135,
            InitialSpawnTime = 102,
            Monsters = new[]
            {
                new MonsterData("Ancient Krug", new Vector3(8526, 0, 2736), 1350),
                new MonsterData("Krug", new Vector3(8700, 0, 2600), 650),
            }
        });

        // === RED SIDE JUNGLE (mirrored) ===
        _camps.Add(new JungleCamp
        {
            Name = "Blue Sentinel (Red)",
            Type = CampType.Buff,
            Side = TeamId.Red,
            GoldReward = 100,
            XpReward = 110,
            RespawnTime = 300,
            InitialSpawnTime = 90,
            Monsters = new[]
            {
                new MonsterData("Blue Sentinel", new Vector3(10984, 0, 6910), 2100),
                new MonsterData("Sentry", new Vector3(10800, 0, 7050), 400),
                new MonsterData("Sentry", new Vector3(11150, 0, 7000), 400),
            }
        });

        _camps.Add(new JungleCamp
        {
            Name = "Gromp (Red)",
            Type = CampType.Small,
            Side = TeamId.Red,
            GoldReward = 80,
            XpReward = 135,
            RespawnTime = 135,
            InitialSpawnTime = 102,
            Monsters = new[]
            {
                new MonsterData("Gromp", new Vector3(12671, 0, 6306), 1800),
            }
        });

        _camps.Add(new JungleCamp
        {
            Name = "Wolves (Red)",
            Type = CampType.Small,
            Side = TeamId.Red,
            GoldReward = 68,
            XpReward = 95,
            RespawnTime = 135,
            InitialSpawnTime = 102,
            Monsters = new[]
            {
                new MonsterData("Greater Murk Wolf", new Vector3(10983, 0, 8328), 1600),
                new MonsterData("Murk Wolf", new Vector3(10800, 0, 8200), 480),
                new MonsterData("Murk Wolf", new Vector3(11150, 0, 8200), 480),
            }
        });

        _camps.Add(new JungleCamp
        {
            Name = "Raptors (Red)",
            Type = CampType.Small,
            Side = TeamId.Red,
            GoldReward = 85,
            XpReward = 95,
            RespawnTime = 135,
            InitialSpawnTime = 102,
            Monsters = new[]
            {
                new MonsterData("Crimson Raptor", new Vector3(7852, 0, 9382), 1100),
                new MonsterData("Raptor", new Vector3(7700, 0, 9250), 425),
                new MonsterData("Raptor", new Vector3(8000, 0, 9200), 425),
                new MonsterData("Raptor", new Vector3(7650, 0, 9500), 425),
                new MonsterData("Raptor", new Vector3(8050, 0, 9550), 425),
                new MonsterData("Raptor", new Vector3(7800, 0, 9650), 425),
            }
        });

        _camps.Add(new JungleCamp
        {
            Name = "Red Brambleback (Red)",
            Type = CampType.Buff,
            Side = TeamId.Red,
            GoldReward = 100,
            XpReward = 110,
            RespawnTime = 300,
            InitialSpawnTime = 90,
            Monsters = new[]
            {
                new MonsterData("Red Brambleback", new Vector3(6945, 0, 10696), 2100),
                new MonsterData("Cinderling", new Vector3(6800, 0, 10550), 400),
                new MonsterData("Cinderling", new Vector3(7100, 0, 10600), 400),
            }
        });

        _camps.Add(new JungleCamp
        {
            Name = "Krugs (Red)",
            Type = CampType.Small,
            Side = TeamId.Red,
            GoldReward = 96,
            XpReward = 128,
            RespawnTime = 135,
            InitialSpawnTime = 102,
            Monsters = new[]
            {
                new MonsterData("Ancient Krug", new Vector3(6317, 0, 12052), 1350),
                new MonsterData("Krug", new Vector3(6150, 0, 11900), 650),
            }
        });

        // === EPIC MONSTERS ===
        _camps.Add(new JungleCamp
        {
            Name = "Dragon",
            Type = CampType.Dragon,
            Side = TeamId.Blue, // Neutral
            GoldReward = 25, // Global gold
            XpReward = 200,
            RespawnTime = 300, // 5 min
            InitialSpawnTime = 300, // 5:00
            Monsters = new[]
            {
                new MonsterData("Elemental Dragon", new Vector3(9866, 0, 4414), 5500),
            }
        });

        _camps.Add(new JungleCamp
        {
            Name = "Rift Herald",
            Type = CampType.Herald,
            Side = TeamId.Blue,
            GoldReward = 100,
            XpReward = 200,
            RespawnTime = 360, // 6 min
            InitialSpawnTime = 480, // 8:00
            Monsters = new[]
            {
                new MonsterData("Rift Herald", new Vector3(4993, 0, 10491), 10000),
            }
        });

        _camps.Add(new JungleCamp
        {
            Name = "Baron Nashor",
            Type = CampType.Baron,
            Side = TeamId.Blue,
            GoldReward = 300, // Per player
            XpReward = 600,
            RespawnTime = 360, // 6 min
            InitialSpawnTime = 1200, // 20:00
            Monsters = new[]
            {
                new MonsterData("Baron Nashor", new Vector3(4993, 0, 10491), 13500),
            }
        });

        // Scuttle Crabs
        _camps.Add(new JungleCamp
        {
            Name = "Rift Scuttler (Bot)",
            Type = CampType.Scuttle,
            Side = TeamId.Blue,
            GoldReward = 70,
            XpReward = 115,
            RespawnTime = 150, // 2:30
            InitialSpawnTime = 210, // 3:30
            Monsters = new[]
            {
                new MonsterData("Rift Scuttler", new Vector3(10500, 0, 5170), 1050),
            }
        });

        _camps.Add(new JungleCamp
        {
            Name = "Rift Scuttler (Top)",
            Type = CampType.Scuttle,
            Side = TeamId.Blue,
            GoldReward = 70,
            XpReward = 115,
            RespawnTime = 150,
            InitialSpawnTime = 210,
            Monsters = new[]
            {
                new MonsterData("Rift Scuttler", new Vector3(4400, 0, 9600), 1050),
            }
        });
    }
}

public class JungleCamp
{
    public string Name { get; set; } = "";
    public CampType Type { get; set; }
    public TeamId Side { get; set; }
    public float GoldReward { get; set; }
    public float XpReward { get; set; }
    public float RespawnTime { get; set; }
    public float InitialSpawnTime { get; set; }
    public float RespawnTimer { get; set; }
    public bool IsAlive { get; set; }
    public MonsterData[] Monsters { get; set; } = Array.Empty<MonsterData>();
}

public record MonsterData(string Name, Vector3 Position, float Health);

public enum CampType
{
    Small, Buff, Dragon, Baron, Herald, Scuttle
}
