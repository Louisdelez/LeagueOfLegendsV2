using System.Collections.Generic;
using LoLServer.Core.Config;
using LoLServer.Core.Game.Buffs;

namespace LoLServer.Core.Game.Entities;

/// <summary>
/// Player champion entity with full stats, inventory, abilities.
/// </summary>
public class Champion : GameEntity, IKillable, IAttacker, IMovable
{
    // Ownership
    public ushort OwnerClientId { get; set; }
    public string ChampionName { get; set; } = "";
    public int SkinId { get; set; }
    public string SummonerName { get; set; } = "";

    // Level
    public int Level { get; set; } = 1;
    public float Experience { get; set; }
    public float ExperienceToNextLevel => Level * 100 + 80; // Simplified

    // IKillable
    public float Health { get; set; } = 600;
    public float MaxHealth { get; set; } = 600;
    public float Mana { get; set; } = 300;
    public float MaxMana { get; set; } = 300;
    public float HealthRegen { get; set; } = 5.5f;
    public float ManaRegen { get; set; } = 7.0f;

    // IAttacker
    public float AttackDamage { get; set; } = 60;
    public float AbilityPower { get; set; }
    public float AttackRange { get; set; } = 550;
    public float AttackSpeed { get; set; } = 0.625f;
    public float AttackCooldown { get; set; }

    // Defense
    public float Armor { get; set; } = 30;
    public float MagicResist { get; set; } = 30;
    public float Shield { get; set; }

    // Offensive stats
    public float AbilityHaste { get; set; }
    public float CritChance { get; set; }
    public float Lethality { get; set; }
    public float ArmorPenPercent { get; set; }
    public float MagicPenFlat { get; set; }
    public float MagicPenPercent { get; set; }
    public float Lifesteal { get; set; }
    public float Omnivamp { get; set; }
    public float Tenacity { get; set; }
    public float GrievousWoundsReduction { get; set; }

    // IMovable
    public float MoveSpeed { get; set; } = 340;
    public Vector3? MoveTarget { get; set; }

    // Resources
    public float Gold { get; set; } = 500;
    public int Kills { get; set; }
    public int Deaths { get; set; }
    public int Assists { get; set; }
    public int CreepScore { get; set; }

    // Abilities
    public AbilitySlot[] Abilities { get; set; } = new AbilitySlot[6]; // Q W E R D F
    public string SummonerSpell1 { get; set; } = "SummonerFlash";
    public string SummonerSpell2 { get; set; } = "SummonerIgnite";

    // Inventory (6 item slots)
    public int[] Items { get; set; } = new int[6];

    // Buffs
    public BuffManager Buffs { get; set; } = new();

    // State
    public bool IsDead { get; set; }
    public bool JustRespawned { get; set; }
    public float RespawnTimer { get; set; }
    public Vector3 SpawnPosition { get; set; }

    public Champion()
    {
        for (int i = 0; i < 6; i++)
            Abilities[i] = new AbilitySlot();
    }

    public override void Update(float deltaTime, GameLoop game)
    {
        if (IsDead)
        {
            RespawnTimer -= deltaTime;
            if (RespawnTimer <= 0)
            {
                Respawn();
            }
            return;
        }

        // Update buffs
        Buffs.Update(deltaTime, this, game);

        // Health/Mana regen
        Health = System.MathF.Min(Health + HealthRegen * deltaTime, MaxHealth);
        Mana = System.MathF.Min(Mana + ManaRegen * deltaTime, MaxMana);

        // Ability cooldowns
        foreach (var ability in Abilities)
        {
            if (ability.CurrentCooldown > 0)
                ability.CurrentCooldown -= deltaTime;
        }

        // Attack cooldown
        if (AttackCooldown > 0)
            AttackCooldown -= deltaTime;

        // Movement
        if (MoveTarget.HasValue)
        {
            var dir = Position.DirectionTo(MoveTarget.Value);
            var dist = Position.Distance2D(MoveTarget.Value);
            var moveAmount = MoveSpeed * deltaTime;

            if (dist <= moveAmount)
            {
                Position = MoveTarget.Value;
                MoveTarget = null;
            }
            else
            {
                Position = new Vector3(
                    Position.X + dir.X * moveAmount,
                    Position.Y,
                    Position.Z + dir.Z * moveAmount
                );
            }
        }
    }

    /// <summary>
    /// Apply damage to this champion, consuming Shield first.
    /// Returns actual HP lost.
    /// </summary>
    public float ApplyDamage(float damage)
    {
        // Grievous wounds reduces healing, not damage - but shields absorb damage
        if (Shield > 0)
        {
            if (Shield >= damage)
            {
                Shield -= damage;
                return 0;
            }
            damage -= Shield;
            Shield = 0;
        }
        Health = System.MathF.Max(0, Health - damage);
        return damage;
    }

    /// <summary>
    /// Get effective cooldown after Ability Haste.
    /// AH formula: actualCD = baseCD * 100 / (100 + AH)
    /// </summary>
    public float GetEffectiveCooldown(float baseCooldown)
    {
        return baseCooldown * 100f / (100f + AbilityHaste);
    }

    public void Die(GameEntity? killer)
    {
        IsDead = true;
        Deaths++;
        Health = 0;
        Shield = 0;
        RespawnTimer = 10 + Level * 2; // Simplified respawn timer
        MoveTarget = null;

        if (killer is Champion killerChamp)
        {
            killerChamp.Kills++;
            killerChamp.Gold += 300; // Base kill gold
        }
    }

    public void Respawn()
    {
        IsDead = false;
        JustRespawned = true;
        Health = MaxHealth;
        Mana = MaxMana;
        Position = SpawnPosition;
    }

    public void AddExperience(float xp)
    {
        Experience += xp;
        while (Experience >= ExperienceToNextLevel && Level < 18)
        {
            Experience -= ExperienceToNextLevel;
            LevelUp();
        }
    }

    private void LevelUp()
    {
        Level++;
        MaxHealth += 90;
        Health += 90;
        MaxMana += 40;
        Mana += 40;
        AttackDamage += 3;
        Armor += 4;
        MagicResist += 1.3f;
    }
}

public class AbilitySlot
{
    public int Level { get; set; }
    public float Cooldown { get; set; } = 10;
    public float CurrentCooldown { get; set; }
    public float ManaCost { get; set; } = 50;
}
