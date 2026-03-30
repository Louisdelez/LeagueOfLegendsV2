using System.Collections.Generic;
using LoLServer.Core.Config;

namespace LoLServer.Core.Game.Entities;

public enum MinionType
{
    Melee,
    Caster,
    Cannon,
    Super
}

/// <summary>
/// Lane minion (sbire) that follows waypoints and attacks enemies.
/// </summary>
public class Minion : GameEntity, IKillable, IAttacker, IMovable
{
    public MinionType MinionType { get; set; }
    public string Lane { get; set; } = "";

    // IKillable
    public float Health { get; set; }
    public float MaxHealth { get; set; }

    // IAttacker
    public float AttackDamage { get; set; }
    public float AttackRange { get; set; }
    public float AttackSpeed { get; set; } = 0.625f;
    public float AttackCooldown { get; set; }

    // IMovable
    public float MoveSpeed { get; set; } = 325;
    public Vector3? MoveTarget { get; set; }

    // Pathfinding
    public List<Vector3> Waypoints { get; set; } = new();
    private int _currentWaypointIndex;
    private GameEntity? _target;

    // Gold/XP rewards
    public float GoldReward => MinionType switch
    {
        MinionType.Melee => 21,
        MinionType.Caster => 14,
        MinionType.Cannon => 60,
        MinionType.Super => 40,
        _ => 14
    };

    public float XpReward => MinionType switch
    {
        MinionType.Melee => 60,
        MinionType.Caster => 32,
        MinionType.Cannon => 93,
        MinionType.Super => 97,
        _ => 32
    };

    public override void Update(float deltaTime, GameLoop game)
    {
        if (Health <= 0) return;

        // Attack cooldown
        if (AttackCooldown > 0)
            AttackCooldown -= deltaTime;

        // Find nearest enemy target in range
        _target = FindNearestEnemy(game);

        if (_target != null && Position.Distance2D(_target.Position) <= AttackRange)
        {
            // Attack target
            if (AttackCooldown <= 0)
            {
                Attack(_target);
                AttackCooldown = 1.0f / AttackSpeed;
            }
        }
        else
        {
            // Follow waypoints
            MoveAlongWaypoints(deltaTime);
        }
    }

    private void MoveAlongWaypoints(float deltaTime)
    {
        if (Waypoints.Count == 0) return;

        if (_currentWaypointIndex >= Waypoints.Count)
            return; // Reached end

        var target = Waypoints[_currentWaypointIndex];
        var dist = Position.Distance2D(target);
        var moveAmount = MoveSpeed * deltaTime;

        if (dist <= moveAmount)
        {
            Position = target;
            _currentWaypointIndex++;
        }
        else
        {
            var dir = Position.DirectionTo(target);
            Position = new Vector3(
                Position.X + dir.X * moveAmount,
                Position.Y,
                Position.Z + dir.Z * moveAmount
            );
        }
    }

    private GameEntity? FindNearestEnemy(GameLoop game)
    {
        GameEntity? nearest = null;
        float nearestDist = AttackRange + 200; // Aggro range

        foreach (var entity in game.Entities)
        {
            if (entity.Team == Team || !entity.IsTargetable) continue;
            if (entity is IKillable k && k.Health <= 0) continue;

            var dist = Position.Distance2D(entity.Position);
            if (dist < nearestDist)
            {
                nearestDist = dist;
                nearest = entity;
            }
        }

        return nearest;
    }

    private void Attack(GameEntity target)
    {
        if (target is IKillable killable)
        {
            killable.Health -= AttackDamage;
        }
    }
}
