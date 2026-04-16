using System;
using System.Collections.Generic;
using System.Linq;
using LoLServer.Core.Game.Entities;
using LoLServer.Core.Game.Combat;

namespace LoLServer.Core.Game.Buffs;

/// <summary>
/// Manages temporary buffs on champions (Blue, Red, Baron, Dragon, item effects, etc.)
/// </summary>
public class BuffManager
{
    private readonly List<Buff> _activeBuffs = new();

    public IReadOnlyList<Buff> ActiveBuffs => _activeBuffs;

    /// <summary>
    /// Update all buffs, remove expired ones, apply per-tick effects.
    /// </summary>
    public void Update(float deltaTime, Champion champion, GameLoop game)
    {
        for (int i = _activeBuffs.Count - 1; i >= 0; i--)
        {
            var buff = _activeBuffs[i];
            buff.RemainingDuration -= deltaTime;

            // Per-tick effects
            buff.TickTimer -= deltaTime;
            if (buff.TickTimer <= 0 && buff.RemainingDuration > 0)
            {
                ApplyTickEffect(buff, champion);
                buff.TickTimer = buff.TickInterval;
            }

            if (buff.RemainingDuration <= 0)
            {
                RemoveBuffEffects(buff, champion);
                _activeBuffs.RemoveAt(i);
            }
        }
    }

    /// <summary>
    /// Add a buff to the champion. If already present, refresh duration (or stack).
    /// </summary>
    public void AddBuff(Buff buff, Champion champion)
    {
        var existing = _activeBuffs.FirstOrDefault(b => b.Type == buff.Type);
        if (existing != null)
        {
            if (buff.Stackable)
            {
                existing.Stacks = Math.Min(existing.Stacks + 1, existing.MaxStacks);
                existing.RemainingDuration = buff.Duration;
            }
            else
            {
                // Refresh duration
                existing.RemainingDuration = buff.Duration;
            }
            return;
        }

        buff.RemainingDuration = buff.Duration;
        buff.TickTimer = buff.TickInterval;
        _activeBuffs.Add(buff);
        ApplyOnApplyEffects(buff, champion);
    }

    public void RemoveBuff(BuffType type, Champion champion)
    {
        var buff = _activeBuffs.FirstOrDefault(b => b.Type == type);
        if (buff != null)
        {
            RemoveBuffEffects(buff, champion);
            _activeBuffs.Remove(buff);
        }
    }

    public bool HasBuff(BuffType type) => _activeBuffs.Any(b => b.Type == type);
    public int GetStacks(BuffType type) => _activeBuffs.FirstOrDefault(b => b.Type == type)?.Stacks ?? 0;

    /// <summary>
    /// Get bonus on-hit damage from buffs (Red buff, etc.)
    /// </summary>
    public float GetBonusOnHitDamage(Champion attacker, GameEntity target)
    {
        float bonus = 0;

        if (HasBuff(BuffType.RedBuff))
        {
            // Red buff: 10 + 2*level true damage over 3s on hit (simplified as instant)
            bonus += 10 + 2 * attacker.Level;
        }

        if (HasBuff(BuffType.BaronBuff))
        {
            // Baron empowered recall + bonus AD/AP (already applied on add)
        }

        return bonus;
    }

    private void ApplyOnApplyEffects(Buff buff, Champion champion)
    {
        switch (buff.Type)
        {
            case BuffType.BlueBuff:
                champion.AbilityHaste += 10;
                champion.ManaRegen += champion.MaxMana * 0.01f; // 1% max mana regen/s
                break;

            case BuffType.RedBuff:
                // On-hit effect handled in GetBonusOnHitDamage
                break;

            case BuffType.BaronBuff:
                champion.AttackDamage += 12 + champion.Level * 1.5f;
                champion.AbilityPower += 12 + champion.Level * 1.5f;
                break;

            case BuffType.DragonInfernal:
                // +4% AD and AP per stack (simplified as flat)
                champion.AttackDamage *= 1.04f;
                champion.AbilityPower = Math.Max(champion.AbilityPower * 1.04f, champion.AbilityPower + 4);
                break;

            case BuffType.DragonMountain:
                champion.Armor += 6;
                champion.MagicResist += 6;
                break;

            case BuffType.DragonOcean:
                champion.HealthRegen += 2.5f;
                break;

            case BuffType.DragonCloud:
                champion.MoveSpeed += 7;
                break;

            case BuffType.DragonHextechSoul:
                // Chain lightning on hit - not stat-based
                break;

            case BuffType.DragonInfernalSoul:
                // Explosion on hit - not stat-based
                break;

            case BuffType.ElderDragon:
                // Execute enemies below 20% HP - checked in combat
                break;

            case BuffType.Conqueror:
                // Stacking AD
                champion.AttackDamage += 2 * buff.Stacks;
                break;

            case BuffType.SpellShield:
                // Blocks next ability
                break;

            case BuffType.Stasis:
                champion.IsTargetable = false;
                break;

            case BuffType.Slow:
                champion.MoveSpeed *= (1f - buff.Value / 100f);
                break;

            case BuffType.Haste:
                champion.MoveSpeed *= (1f + buff.Value / 100f);
                break;

            case BuffType.Ignite:
                // Tick damage handled in ApplyTickEffect
                champion.GrievousWoundsReduction = 40;
                break;

            case BuffType.Exhaust:
                champion.MoveSpeed *= 0.7f;
                champion.AttackDamage *= 0.6f;
                break;
        }
    }

    private void RemoveBuffEffects(Buff buff, Champion champion)
    {
        switch (buff.Type)
        {
            case BuffType.BlueBuff:
                champion.AbilityHaste -= 10;
                champion.ManaRegen -= champion.MaxMana * 0.01f;
                break;

            case BuffType.BaronBuff:
                champion.AttackDamage -= 12 + champion.Level * 1.5f;
                champion.AbilityPower -= 12 + champion.Level * 1.5f;
                break;

            case BuffType.DragonMountain:
                champion.Armor -= 6;
                champion.MagicResist -= 6;
                break;

            case BuffType.DragonOcean:
                champion.HealthRegen -= 2.5f;
                break;

            case BuffType.DragonCloud:
                champion.MoveSpeed -= 7;
                break;

            case BuffType.Conqueror:
                champion.AttackDamage -= 2 * buff.Stacks;
                break;

            case BuffType.Stasis:
                champion.IsTargetable = true;
                break;

            case BuffType.Slow:
                champion.MoveSpeed /= (1f - buff.Value / 100f);
                break;

            case BuffType.Haste:
                champion.MoveSpeed /= (1f + buff.Value / 100f);
                break;

            case BuffType.Ignite:
                champion.GrievousWoundsReduction = 0;
                break;

            case BuffType.Exhaust:
                champion.MoveSpeed /= 0.7f;
                champion.AttackDamage /= 0.6f;
                break;
        }
    }

    private void ApplyTickEffect(Buff buff, Champion champion)
    {
        switch (buff.Type)
        {
            case BuffType.Ignite:
                // Tick true damage
                champion.Health -= buff.Value;
                break;

            case BuffType.RedBuff:
                // DoT: already simplified as on-hit
                break;

            case BuffType.Poison:
                champion.Health -= buff.Value;
                break;
        }
    }

    // ============== FACTORY METHODS ==============

    public static Buff CreateBlueBuff() => new()
    {
        Type = BuffType.BlueBuff, Duration = 120, Name = "Crest of Insight",
        TickInterval = 999 // No tick
    };

    public static Buff CreateRedBuff() => new()
    {
        Type = BuffType.RedBuff, Duration = 120, Name = "Crest of Cinders",
        TickInterval = 1
    };

    public static Buff CreateBaronBuff() => new()
    {
        Type = BuffType.BaronBuff, Duration = 180, Name = "Hand of Baron",
        TickInterval = 999
    };

    public static Buff CreateDragonBuff(DragonElement element) => new()
    {
        Type = element switch
        {
            DragonElement.Infernal => BuffType.DragonInfernal,
            DragonElement.Mountain => BuffType.DragonMountain,
            DragonElement.Ocean => BuffType.DragonOcean,
            DragonElement.Cloud => BuffType.DragonCloud,
            DragonElement.Hextech => BuffType.DragonInfernal, // Simplified
            DragonElement.Chemtech => BuffType.DragonOcean,   // Simplified
            _ => BuffType.DragonInfernal
        },
        Duration = float.MaxValue, // Permanent
        Name = $"{element} Dragon",
        Stackable = true,
        MaxStacks = 4,
        TickInterval = 999
    };

    public static Buff CreateDragonSoul(DragonElement element) => new()
    {
        Type = element switch
        {
            DragonElement.Infernal => BuffType.DragonInfernalSoul,
            DragonElement.Hextech => BuffType.DragonHextechSoul,
            _ => BuffType.DragonInfernalSoul
        },
        Duration = float.MaxValue,
        Name = $"{element} Dragon Soul",
        TickInterval = 999
    };

    public static Buff CreateElderDragonBuff() => new()
    {
        Type = BuffType.ElderDragon, Duration = 150, Name = "Aspect of the Dragon",
        TickInterval = 999
    };

    public static Buff CreateIgniteBuff(float dps) => new()
    {
        Type = BuffType.Ignite, Duration = 5, Name = "Ignite",
        Value = dps, TickInterval = 0.5f
    };

    public static Buff CreateExhaustBuff() => new()
    {
        Type = BuffType.Exhaust, Duration = 3, Name = "Exhaust",
        TickInterval = 999
    };

    public static Buff CreateSlowBuff(float percent, float duration) => new()
    {
        Type = BuffType.Slow, Duration = duration, Name = "Slow",
        Value = percent, TickInterval = 999
    };

    public static Buff CreateHasteBuff(float percent, float duration) => new()
    {
        Type = BuffType.Haste, Duration = duration, Name = "Haste",
        Value = percent, TickInterval = 999
    };

    public static Buff CreateStasisBuff() => new()
    {
        Type = BuffType.Stasis, Duration = 2.5f, Name = "Stasis",
        TickInterval = 999
    };

    public static Buff CreateShieldBuff(float shieldAmount, float duration) => new()
    {
        Type = BuffType.SpellShield, Duration = duration, Name = "Shield",
        Value = shieldAmount, TickInterval = 999
    };
}

public class Buff
{
    public BuffType Type { get; set; }
    public string Name { get; set; } = "";
    public float Duration { get; set; }
    public float RemainingDuration { get; set; }
    public float Value { get; set; }
    public float TickInterval { get; set; } = 1;
    public float TickTimer { get; set; }
    public bool Stackable { get; set; }
    public int Stacks { get; set; } = 1;
    public int MaxStacks { get; set; } = 1;
}

public enum BuffType
{
    // Jungle buffs
    BlueBuff, RedBuff, BaronBuff,
    // Dragon stacks
    DragonInfernal, DragonMountain, DragonOcean, DragonCloud,
    // Dragon souls
    DragonInfernalSoul, DragonHextechSoul,
    // Elder
    ElderDragon,
    // Summoner spells
    Ignite, Exhaust,
    // CC / Movement
    Slow, Haste, Stun, Root, Silence, Knockup,
    // Defensive
    SpellShield, Stasis,
    // Rune
    Conqueror,
    // Item
    Poison, GrievousWounds,
    // Generic
    AttackSpeedBuff, ArmorBuff, MagicResistBuff
}

public enum DragonElement
{
    Infernal, Mountain, Ocean, Cloud, Hextech, Chemtech
}
