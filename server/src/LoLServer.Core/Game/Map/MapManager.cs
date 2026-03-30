using System.Collections.Generic;
using LoLServer.Core.Config;
using LoLServer.Core.Game.Entities;

namespace LoLServer.Core.Game.Map;

/// <summary>
/// Map data manager. Contains positions of turrets, inhibitors, spawn points,
/// lane waypoints, and jungle camps for each map type.
/// </summary>
public class MapManager
{
    public int MapId { get; }
    public float Width { get; }
    public float Height { get; }

    public MapManager(int mapId)
    {
        MapId = mapId;
        var size = GetMapSize();
        Width = size.X;
        Height = size.Z;
    }

    private Vector3 GetMapSize() => MapId switch
    {
        11 => new Vector3(14870, 0, 14980), // Summoner's Rift
        12 => new Vector3(13100, 0, 12600), // ARAM
        _ => new Vector3(14870, 0, 14980)
    };

    // ============== SPAWN POSITIONS ==============

    public Vector3 GetBlueSpawn() => MapId switch
    {
        11 => new Vector3(394, 0, 461),
        12 => new Vector3(52, 0, 6300),
        _ => new Vector3(394, 0, 461)
    };

    public Vector3 GetRedSpawn() => MapId switch
    {
        11 => new Vector3(14340, 0, 14390),
        12 => new Vector3(13050, 0, 6300),
        _ => new Vector3(14340, 0, 14390)
    };

    // ============== TURRETS ==============

    public List<TurretData> GetTurrets()
    {
        return MapId switch
        {
            11 => GetSummonersRiftTurrets(),
            12 => GetAramTurrets(),
            _ => GetSummonersRiftTurrets()
        };
    }

    private List<TurretData> GetSummonersRiftTurrets()
    {
        return new List<TurretData>
        {
            // === BLUE TEAM ===
            // Top lane
            new("Turret_T1_R_03", TeamId.Blue, new(981, 0, 10441), 1800, 152, 775),
            new("Turret_T1_R_02", TeamId.Blue, new(1512, 0, 6699), 2550, 170, 775),
            new("Turret_T1_C_06", TeamId.Blue, new(1169, 0, 4287), 2550, 170, 775),

            // Mid lane
            new("Turret_T1_C_05", TeamId.Blue, new(5048, 0, 4812), 1800, 152, 775),
            new("Turret_T1_C_04", TeamId.Blue, new(5166, 0, 3017), 2550, 170, 775),
            new("Turret_T1_C_03", TeamId.Blue, new(3651, 0, 3696), 2550, 170, 775),

            // Bot lane
            new("Turret_T1_L_03", TeamId.Blue, new(10504, 0, 1029), 1800, 152, 775),
            new("Turret_T1_L_02", TeamId.Blue, new(6919, 0, 1483), 2550, 170, 775),
            new("Turret_T1_C_07", TeamId.Blue, new(4281, 0, 1253), 2550, 170, 775),

            // Nexus turrets
            new("Turret_T1_C_01", TeamId.Blue, new(1748, 0, 2270), 2550, 180, 775),
            new("Turret_T1_C_02", TeamId.Blue, new(2177, 0, 1807), 2550, 180, 775),

            // === RED TEAM ===
            // Top lane
            new("Turret_T2_R_03", TeamId.Red, new(4318, 0, 13875), 1800, 152, 775),
            new("Turret_T2_R_02", TeamId.Red, new(7943, 0, 13411), 2550, 170, 775),
            new("Turret_T2_R_01", TeamId.Red, new(10481, 0, 13650), 2550, 170, 775),

            // Mid lane
            new("Turret_T2_C_05", TeamId.Red, new(9767, 0, 10113), 1800, 152, 775),
            new("Turret_T2_C_04", TeamId.Red, new(9768, 0, 11884), 2550, 170, 775),
            new("Turret_T2_C_03", TeamId.Red, new(11134, 0, 11207), 2550, 170, 775),

            // Bot lane
            new("Turret_T2_L_03", TeamId.Red, new(13866, 0, 4505), 1800, 152, 775),
            new("Turret_T2_L_02", TeamId.Red, new(13327, 0, 8226), 2550, 170, 775),
            new("Turret_T2_L_01", TeamId.Red, new(13624, 0, 10572), 2550, 170, 775),

            // Nexus turrets
            new("Turret_T2_C_01", TeamId.Red, new(12611, 0, 13084), 2550, 180, 775),
            new("Turret_T2_C_02", TeamId.Red, new(13052, 0, 12612), 2550, 180, 775),
        };
    }

    private List<TurretData> GetAramTurrets()
    {
        // ARAM - single lane, 4 turrets per team
        return new List<TurretData>
        {
            // Blue team (left side)
            new("Turret_T1_01", TeamId.Blue, new(1550, 0, 6300), 2550, 170, 775),
            new("Turret_T1_02", TeamId.Blue, new(3400, 0, 6300), 1800, 152, 775),
            new("Turret_T1_03", TeamId.Blue, new(5200, 0, 6300), 1800, 152, 775),
            new("Turret_T1_N1", TeamId.Blue, new(800, 0, 6600), 2550, 180, 775),

            // Red team (right side)
            new("Turret_T2_01", TeamId.Red, new(11500, 0, 6300), 2550, 170, 775),
            new("Turret_T2_02", TeamId.Red, new(9700, 0, 6300), 1800, 152, 775),
            new("Turret_T2_03", TeamId.Red, new(7900, 0, 6300), 1800, 152, 775),
            new("Turret_T2_N1", TeamId.Red, new(12300, 0, 6000), 2550, 180, 775),
        };
    }

    // ============== INHIBITORS ==============

    public List<InhibitorData> GetInhibitors()
    {
        return MapId switch
        {
            11 => new List<InhibitorData>
            {
                new("Inhibitor_T1_R", TeamId.Blue, new(1171, 0, 3571)),  // Top
                new("Inhibitor_T1_C", TeamId.Blue, new(3203, 0, 3208)),  // Mid
                new("Inhibitor_T1_L", TeamId.Blue, new(3452, 0, 1236)),  // Bot
                new("Inhibitor_T2_R", TeamId.Red, new(11261, 0, 13676)), // Top
                new("Inhibitor_T2_C", TeamId.Red, new(11598, 0, 11667)),// Mid
                new("Inhibitor_T2_L", TeamId.Red, new(13604, 0, 11316)),// Bot
            },
            12 => new List<InhibitorData>
            {
                new("Inhibitor_T1", TeamId.Blue, new(2200, 0, 6300)),
                new("Inhibitor_T2", TeamId.Red, new(10900, 0, 6300)),
            },
            _ => new List<InhibitorData>()
        };
    }

    // ============== NEXUS ==============

    public List<NexusData> GetNexusPositions()
    {
        return MapId switch
        {
            11 => new List<NexusData>
            {
                new("Nexus_T1", TeamId.Blue, new(1984, 0, 2040)),
                new("Nexus_T2", TeamId.Red, new(12800, 0, 12843)),
            },
            12 => new List<NexusData>
            {
                new("Nexus_T1", TeamId.Blue, new(400, 0, 6300)),
                new("Nexus_T2", TeamId.Red, new(12700, 0, 6300)),
            },
            _ => new List<NexusData>()
        };
    }

    // ============== LANES & WAYPOINTS ==============

    public List<LaneData> GetLanes()
    {
        return MapId switch
        {
            11 => GetSummonersRiftLanes(),
            12 => GetAramLanes(),
            _ => GetSummonersRiftLanes()
        };
    }

    private List<LaneData> GetSummonersRiftLanes()
    {
        return new List<LaneData>
        {
            new LaneData
            {
                Name = "Top",
                BlueSpawn = new(1341, 0, 3892),
                RedSpawn = new(10936, 0, 13432),
                BlueWaypoints = new()
                {
                    new(1341, 0, 3892), new(981, 0, 7000), new(981, 0, 10441),
                    new(2000, 0, 12500), new(4318, 0, 13875), new(7943, 0, 13411),
                    new(10481, 0, 13650), new(11261, 0, 13676), new(12800, 0, 12843),
                },
                RedWaypoints = new()
                {
                    new(10936, 0, 13432), new(10481, 0, 13650), new(7943, 0, 13411),
                    new(4318, 0, 13875), new(2000, 0, 12500), new(981, 0, 10441),
                    new(981, 0, 7000), new(1341, 0, 3892), new(1984, 0, 2040),
                }
            },
            new LaneData
            {
                Name = "Mid",
                BlueSpawn = new(3203, 0, 3208),
                RedSpawn = new(11598, 0, 11667),
                BlueWaypoints = new()
                {
                    new(3203, 0, 3208), new(5048, 0, 4812), new(7450, 0, 7450),
                    new(9767, 0, 10113), new(11598, 0, 11667), new(12800, 0, 12843),
                },
                RedWaypoints = new()
                {
                    new(11598, 0, 11667), new(9767, 0, 10113), new(7450, 0, 7450),
                    new(5048, 0, 4812), new(3203, 0, 3208), new(1984, 0, 2040),
                }
            },
            new LaneData
            {
                Name = "Bot",
                BlueSpawn = new(3452, 0, 1236),
                RedSpawn = new(13604, 0, 11316),
                BlueWaypoints = new()
                {
                    new(3452, 0, 1236), new(6919, 0, 1483), new(10504, 0, 1029),
                    new(12500, 0, 2500), new(13866, 0, 4505), new(13327, 0, 8226),
                    new(13624, 0, 10572), new(13604, 0, 11316), new(12800, 0, 12843),
                },
                RedWaypoints = new()
                {
                    new(13604, 0, 11316), new(13624, 0, 10572), new(13327, 0, 8226),
                    new(13866, 0, 4505), new(12500, 0, 2500), new(10504, 0, 1029),
                    new(6919, 0, 1483), new(3452, 0, 1236), new(1984, 0, 2040),
                }
            }
        };
    }

    private List<LaneData> GetAramLanes()
    {
        return new List<LaneData>
        {
            new LaneData
            {
                Name = "Mid",
                BlueSpawn = new(1200, 0, 6300),
                RedSpawn = new(11900, 0, 6300),
                BlueWaypoints = new()
                {
                    new(1200, 0, 6300), new(3400, 0, 6300), new(5200, 0, 6300),
                    new(6550, 0, 6300), new(7900, 0, 6300), new(9700, 0, 6300),
                    new(11500, 0, 6300), new(12700, 0, 6300),
                },
                RedWaypoints = new()
                {
                    new(11900, 0, 6300), new(9700, 0, 6300), new(7900, 0, 6300),
                    new(6550, 0, 6300), new(5200, 0, 6300), new(3400, 0, 6300),
                    new(1550, 0, 6300), new(400, 0, 6300),
                }
            }
        };
    }
}

// ============== DATA STRUCTS ==============

public record TurretData(string Name, TeamId Team, Vector3 Position, float Health, float Damage, float Range);
public record InhibitorData(string Name, TeamId Team, Vector3 Position);
public record NexusData(string Name, TeamId Team, Vector3 Position);

public class LaneData
{
    public string Name { get; set; } = "";
    public Vector3 BlueSpawn { get; set; }
    public Vector3 RedSpawn { get; set; }
    public List<Vector3> BlueWaypoints { get; set; } = new();
    public List<Vector3> RedWaypoints { get; set; } = new();
}
