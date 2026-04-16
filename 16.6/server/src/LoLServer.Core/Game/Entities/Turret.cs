using LoLServer.Core.Config;

namespace LoLServer.Core.Game.Entities;

/// <summary>
/// Defense turret that attacks nearby enemies. Prioritizes minions,
/// then champions that attack allied champions.
/// </summary>
public class Turret : GameEntity, IKillable, IAttacker
{
    public float Health { get; set; }
    public float MaxHealth { get; set; }
    public float AttackDamage { get; set; }
    public float AttackRange { get; set; } = 775;
    public float AttackSpeed { get; set; } = 0.833f;
    public float AttackCooldown { get; set; }

    private GameEntity? _target;

    public override void Update(float deltaTime, GameLoop game)
    {
        if (Health <= 0) return;

        if (AttackCooldown > 0)
            AttackCooldown -= deltaTime;

        // Find target: prioritize minions, then champions
        _target = FindTarget(game);

        if (_target != null && AttackCooldown <= 0)
        {
            if (_target is IKillable killable)
            {
                killable.Health -= AttackDamage;
            }
            AttackCooldown = 1.0f / AttackSpeed;
        }
    }

    private GameEntity? FindTarget(GameLoop game)
    {
        GameEntity? nearestMinion = null;
        GameEntity? nearestChampion = null;
        float minDist = float.MaxValue;
        float champDist = float.MaxValue;

        foreach (var entity in game.Entities)
        {
            if (entity.Team == Team || !entity.IsTargetable) continue;
            if (entity is IKillable k && k.Health <= 0) continue;

            var dist = Position.Distance2D(entity.Position);
            if (dist > AttackRange) continue;

            if (entity is Minion && dist < minDist)
            {
                minDist = dist;
                nearestMinion = entity;
            }
            else if (entity is Champion && dist < champDist)
            {
                champDist = dist;
                nearestChampion = entity;
            }
        }

        // Prioritize minions
        return nearestMinion ?? nearestChampion;
    }
}

/// <summary>
/// Lane inhibitor. When destroyed, enemy spawns super minions.
/// Respawns after 5 minutes.
/// </summary>
public class Inhibitor : GameEntity, IKillable
{
    public float Health { get; set; }
    public float MaxHealth { get; set; }
    public float RespawnTimer { get; set; }
    public bool IsDestroyed { get; set; }

    private const float RespawnTime = 300f; // 5 minutes

    public override void Update(float deltaTime, GameLoop game)
    {
        if (IsDestroyed)
        {
            RespawnTimer -= deltaTime;
            if (RespawnTimer <= 0)
            {
                IsDestroyed = false;
                Health = MaxHealth;
                IsTargetable = true;
            }
        }
        else if (Health <= 0 && !IsDestroyed)
        {
            IsDestroyed = true;
            IsTargetable = false;
            RespawnTimer = RespawnTime;
        }
    }
}

/// <summary>
/// Team nexus. Game ends when a nexus is destroyed.
/// </summary>
public class Nexus : GameEntity, IKillable
{
    public float Health { get; set; }
    public float MaxHealth { get; set; }
}
