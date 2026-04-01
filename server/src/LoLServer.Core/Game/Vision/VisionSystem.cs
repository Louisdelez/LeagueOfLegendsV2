using System;
using System.Collections.Generic;
using System.Linq;
using LoLServer.Core.Config;
using LoLServer.Core.Game.Entities;

namespace LoLServer.Core.Game.Vision;

/// <summary>
/// Fog of War and vision system.
/// Manages vision sources (champions, wards, turrets, minions) and determines
/// which entities are visible to each team.
/// </summary>
public class VisionSystem
{
    private readonly GameLoop _game;
    private readonly List<Ward> _wards = new();
    private readonly List<BrushZone> _brushZones = new();

    // Vision ranges
    public const float ChampionVisionRange = 1200f;
    public const float TurretVisionRange = 1095f;
    public const float MinionVisionRange = 800f;
    public const float WardVisionRange = 900f;
    public const float ControlWardRange = 900f;
    public const float BrushDetectionRange = 150f;

    // Cached visibility per team (refreshed each tick)
    private readonly HashSet<uint> _blueVisibleEntities = new();
    private readonly HashSet<uint> _redVisibleEntities = new();

    public VisionSystem(GameLoop game)
    {
        _game = game;
        InitializeBrushZones();
    }

    /// <summary>
    /// Update vision for both teams. Call once per tick.
    /// </summary>
    public void Update(float deltaTime)
    {
        // Update ward timers
        for (int i = _wards.Count - 1; i >= 0; i--)
        {
            _wards[i].RemainingDuration -= deltaTime;
            if (_wards[i].RemainingDuration <= 0)
            {
                Console.WriteLine($"[VISION] {_wards[i].Type} ward expired at {_wards[i].Position}");
                _wards.RemoveAt(i);
            }
        }

        // Recalculate visibility
        _blueVisibleEntities.Clear();
        _redVisibleEntities.Clear();

        CalculateTeamVision(TeamId.Blue, _blueVisibleEntities);
        CalculateTeamVision(TeamId.Red, _redVisibleEntities);
    }

    /// <summary>
    /// Check if an entity is visible to a specific team.
    /// </summary>
    public bool IsVisibleTo(uint entityId, TeamId team)
    {
        // Own team entities are always visible
        var entity = _game.GetEntity(entityId);
        if (entity == null) return false;
        if (entity.Team == team) return true;

        return team == TeamId.Blue
            ? _blueVisibleEntities.Contains(entityId)
            : _redVisibleEntities.Contains(entityId);
    }

    /// <summary>
    /// Check if a position is visible to a specific team.
    /// </summary>
    public bool IsPositionVisibleTo(Vector3 position, TeamId team)
    {
        foreach (var source in GetVisionSourcesForTeam(team))
        {
            if (position.Distance2D(source.Position) <= source.Range)
                return true;
        }
        return false;
    }

    /// <summary>
    /// Place a ward at position.
    /// </summary>
    public void PlaceWard(Vector3 position, TeamId team, WardType type)
    {
        var ward = new Ward
        {
            Position = position,
            Team = team,
            Type = type,
            VisionRange = type == WardType.Control ? ControlWardRange : WardVisionRange,
            RemainingDuration = type switch
            {
                WardType.Stealth => 90f,      // 90 seconds (trinket)
                WardType.Control => float.MaxValue, // Until destroyed
                WardType.Farsight => float.MaxValue, // Until destroyed (1 HP)
                WardType.Zombie => 120f,       // Zombie ward
                WardType.GhostPoro => 90f,
                _ => 90f
            },
            MaxHealth = type switch
            {
                WardType.Stealth => 3,
                WardType.Control => 4,
                WardType.Farsight => 1,
                _ => 3
            },
            Health = type switch
            {
                WardType.Stealth => 3,
                WardType.Control => 4,
                WardType.Farsight => 1,
                _ => 3
            },
            IsStealthed = type == WardType.Stealth || type == WardType.GhostPoro
        };

        _wards.Add(ward);
        Console.WriteLine($"[VISION] {team} placed {type} ward at {position} (duration: {ward.RemainingDuration:F0}s)");
    }

    /// <summary>
    /// Destroy a ward (by control ward or oracle lens).
    /// </summary>
    public bool TryDestroyWard(Vector3 position, TeamId attackerTeam, float range = 600f)
    {
        for (int i = _wards.Count - 1; i >= 0; i--)
        {
            var ward = _wards[i];
            if (ward.Team != attackerTeam && ward.Position.Distance2D(position) <= range)
            {
                ward.Health--;
                if (ward.Health <= 0)
                {
                    Console.WriteLine($"[VISION] {attackerTeam} destroyed {ward.Team}'s {ward.Type} ward");
                    _wards.RemoveAt(i);
                    return true;
                }
            }
        }
        return false;
    }

    /// <summary>
    /// Check if entity is inside a brush zone.
    /// </summary>
    public bool IsInBrush(Vector3 position)
    {
        return _brushZones.Any(b => position.Distance2D(b.Center) <= b.Radius);
    }

    /// <summary>
    /// Get all entities visible to a specific champion.
    /// </summary>
    public List<GameEntity> GetVisibleEntities(Champion viewer)
    {
        var visible = new List<GameEntity>();
        foreach (var entity in _game.Entities)
        {
            if (entity.Team == viewer.Team || IsVisibleTo(entity.Id, viewer.Team))
                visible.Add(entity);
        }
        return visible;
    }

    /// <summary>
    /// Get wards for a team.
    /// </summary>
    public IReadOnlyList<Ward> GetWardsForTeam(TeamId team) =>
        _wards.Where(w => w.Team == team).ToList();

    /// <summary>
    /// Reveal stealthed wards near control ward or oracle lens.
    /// </summary>
    public List<Ward> RevealWardsNear(Vector3 position, TeamId team, float range = 900f)
    {
        return _wards
            .Where(w => w.Team != team && w.IsStealthed && w.Position.Distance2D(position) <= range)
            .ToList();
    }

    // ============== INTERNAL ==============

    private void CalculateTeamVision(TeamId team, HashSet<uint> visibleSet)
    {
        var sources = GetVisionSourcesForTeam(team);

        foreach (var entity in _game.Entities)
        {
            if (entity.Team == team) continue; // Own team always visible
            if (!entity.IsTargetable) continue;

            bool visible = false;

            // Check if any vision source can see this entity
            foreach (var source in sources)
            {
                float dist = entity.Position.Distance2D(source.Position);

                if (dist <= source.Range)
                {
                    // Check brush: entities in brush are only visible if vision source is also in brush
                    // or within BrushDetectionRange
                    if (IsInBrush(entity.Position))
                    {
                        if (IsInBrush(source.Position) || dist <= BrushDetectionRange)
                        {
                            visible = true;
                            break;
                        }
                        // Control wards reveal brush
                        if (source.IsControlWard)
                        {
                            visible = true;
                            break;
                        }
                    }
                    else
                    {
                        visible = true;
                        break;
                    }
                }
            }

            if (visible)
                visibleSet.Add(entity.Id);
        }
    }

    private List<VisionSource> GetVisionSourcesForTeam(TeamId team)
    {
        var sources = new List<VisionSource>();

        // Champions
        foreach (var champ in _game.Champions)
        {
            if (champ.Team == team && !champ.IsDead)
            {
                sources.Add(new VisionSource(champ.Position, ChampionVisionRange, false));
            }
        }

        // Turrets
        foreach (var entity in _game.Entities)
        {
            if (entity.Team == team && entity is Turret turret && turret.Health > 0)
            {
                sources.Add(new VisionSource(turret.Position, TurretVisionRange, false));
            }
        }

        // Minions
        foreach (var entity in _game.Entities)
        {
            if (entity.Team == team && entity is Minion minion && minion.Health > 0)
            {
                sources.Add(new VisionSource(minion.Position, MinionVisionRange, false));
            }
        }

        // Wards
        foreach (var ward in _wards)
        {
            if (ward.Team == team)
            {
                sources.Add(new VisionSource(ward.Position, ward.VisionRange, ward.Type == WardType.Control));
            }
        }

        return sources;
    }

    private void InitializeBrushZones()
    {
        if (_game.Map.MapId != 11) return; // SR only

        // Summoner's Rift brush zones (approximate positions and radii)
        // Top lane brushes
        AddBrush(1774, 10756, 200); // Top river brush
        AddBrush(1024, 11726, 200);
        AddBrush(1174, 12626, 180);

        // Mid lane brushes (side bushes)
        AddBrush(5024, 8324, 150); // Left mid brush
        AddBrush(5474, 7274, 150);
        AddBrush(9424, 7124, 150); // Right mid brush
        AddBrush(9874, 6374, 150);

        // Bot lane brushes
        AddBrush(10074, 3074, 200);
        AddBrush(13074, 3574, 200);
        AddBrush(13574, 2824, 180);

        // River brushes
        AddBrush(4824, 9624, 220); // Top river (near dragon pit)
        AddBrush(10224, 5324, 220); // Bot river (near baron pit)

        // Jungle brushes (blue side)
        AddBrush(2874, 8574, 150); // Near blue buff
        AddBrush(6624, 5874, 150); // Near raptors
        AddBrush(8274, 3674, 150); // Near red buff
        AddBrush(7674, 4774, 150); // Near Krugs

        // Jungle brushes (red side)
        AddBrush(12074, 6274, 150); // Near blue buff
        AddBrush(8274, 9074, 150); // Near raptors
        AddBrush(6624, 11074, 150); // Near red buff
        AddBrush(7174, 10074, 150); // Near Krugs

        // Tri-brushes
        AddBrush(2824, 6474, 180); // Top tri
        AddBrush(12074, 3974, 180); // Bot tri
        AddBrush(12624, 8274, 180); // Top-side tri
        AddBrush(2174, 6874, 180); // Bot-side tri

        Console.WriteLine($"[VISION] Initialized {_brushZones.Count} brush zones");
    }

    private void AddBrush(float x, float z, float radius)
    {
        _brushZones.Add(new BrushZone(new Vector3(x, 0, z), radius));
    }
}

public class Ward
{
    public Vector3 Position { get; set; }
    public TeamId Team { get; set; }
    public WardType Type { get; set; }
    public float VisionRange { get; set; }
    public float RemainingDuration { get; set; }
    public int Health { get; set; }
    public int MaxHealth { get; set; }
    public bool IsStealthed { get; set; }
}

public enum WardType
{
    Stealth,    // Trinket / Sightstone
    Control,    // Control Ward (visible, true sight)
    Farsight,   // Blue trinket (1 HP)
    Zombie,     // Zombie Ward rune
    GhostPoro   // Ghost Poro rune
}

public record struct VisionSource(Vector3 Position, float Range, bool IsControlWard);
public record struct BrushZone(Vector3 Center, float Radius);
