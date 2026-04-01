using System;
using LoLServer.Core.Game.Buffs;
using LoLServer.Core.Game.Entities;
using LoLServer.Core.Game.Items;

namespace LoLServer.Core.Game.Combat;

public enum DamageType
{
    Physical,
    Magic,
    True
}

/// <summary>
/// Calculates damage with armor/magic resist reduction.
/// Uses the standard LoL formula: damage * 100 / (100 + resistance)
/// </summary>
public static class DamageCalculator
{
    /// <summary>
    /// Calculate damage with penetration from attacker (if Champion).
    /// </summary>
    public static float CalculateDamage(float rawDamage, DamageType type, GameEntity target, GameEntity? attacker = null)
    {
        if (type == DamageType.True) return rawDamage;

        float resistance = 0;

        if (target is Champion champ)
        {
            resistance = type switch
            {
                DamageType.Physical => champ.Armor,
                DamageType.Magic => champ.MagicResist,
                _ => 0
            };
        }
        else if (target is Turret turret)
        {
            // Turrets have armor only (no MR stat stored, use 0)
            resistance = type == DamageType.Physical ? 40 : 0;
        }
        else if (target is Minion)
        {
            resistance = type == DamageType.Physical ? 0 : 0; // Minions have 0 base
        }

        // Apply penetration from attacker
        if (attacker is Champion attackerChamp)
        {
            if (type == DamageType.Physical)
            {
                // Lethality -> flat armor pen (scales with target level)
                float flatPen = attackerChamp.Lethality * (0.6f + 0.4f * (target is Champion tc ? tc.Level : 9) / 18f);
                // Percent armor pen
                resistance *= (1f - attackerChamp.ArmorPenPercent / 100f);
                resistance -= flatPen;
            }
            else if (type == DamageType.Magic)
            {
                // Percent magic pen first, then flat
                resistance *= (1f - attackerChamp.MagicPenPercent / 100f);
                resistance -= attackerChamp.MagicPenFlat;
            }
        }

        // Resistance can go below 0
        if (resistance >= 0)
        {
            return rawDamage * 100f / (100f + resistance);
        }
        else
        {
            return rawDamage * (2f - 100f / (100f - resistance));
        }
    }

    /// <summary>
    /// Apply auto-attack damage from attacker to target. Handles crit, lifesteal, shield.
    /// </summary>
    public static float ApplyAutoAttack(GameEntity attacker, GameEntity target)
    {
        float ad = 0;
        if (attacker is IAttacker a) ad = a.AttackDamage;

        // Critical strike
        if (attacker is Champion atkChamp)
        {
            float critRoll = Random.Shared.NextSingle() * 100f;
            if (critRoll < atkChamp.CritChance)
            {
                ad *= 1.75f; // Base crit multiplier (175%)
            }
        }

        float damage = CalculateDamage(ad, DamageType.Physical, target, attacker);

        // Item on-hit passives (BotRK, Wit's End, Nashor's, Spellblade, etc.)
        if (attacker is Champion itemAttacker)
        {
            float itemBonusDmg = ItemPassiveManager.ProcessOnHit(itemAttacker, target);
            if (itemBonusDmg > 0)
                damage += itemBonusDmg; // Simplified: added to physical damage

            // Update lifesteal/omnivamp from items
            itemAttacker.Lifesteal = ItemPassiveManager.GetLifestealFromItems(itemAttacker);
            itemAttacker.Omnivamp = ItemPassiveManager.GetOmnivampFromItems(itemAttacker);
        }

        // Apply damage (use Shield-aware method for Champions)
        if (target is Champion targetChamp)
        {
            damage = targetChamp.ApplyDamage(damage);

            // Trigger on-being-hit passives (Thornmail, etc.)
            if (attacker is Champion)
                ItemPassiveManager.ProcessOnBeingHit(targetChamp, attacker, damage);
        }
        else if (target is IKillable killable)
        {
            killable.Health = MathF.Max(0, killable.Health - damage);
        }

        // Item execute check (The Collector < 5%)
        if (attacker is Champion execAttacker && target is IKillable execTarget)
        {
            if (ItemPassiveManager.ShouldExecute(execAttacker, target))
            {
                execTarget.Health = 0;
            }
        }

        // Buff on-hit bonus (Red buff true damage, etc.)
        if (attacker is Champion atkBuff && damage > 0)
        {
            float bonusDmg = atkBuff.Buffs.GetBonusOnHitDamage(atkBuff, target);
            if (bonusDmg > 0)
            {
                // True damage from buffs
                if (target is Champion tc)
                    tc.ApplyDamage(bonusDmg);
                else if (target is IKillable bk)
                    bk.Health = MathF.Max(0, bk.Health - bonusDmg);
            }

            // Elder Dragon execute: enemies below 20% HP
            if (atkBuff.Buffs.HasBuff(BuffType.ElderDragon) && target is IKillable ek)
            {
                if (ek.Health > 0 && ek.Health / ek.MaxHealth < 0.20f)
                {
                    ek.Health = 0; // Execute!
                }
            }
        }

        // Lifesteal
        if (attacker is Champion atkC && damage > 0)
        {
            float heal = damage * (atkC.Lifesteal + atkC.Omnivamp) / 100f;
            if (atkC.GrievousWoundsReduction > 0)
                heal *= (1f - atkC.GrievousWoundsReduction / 100f);
            atkC.Health = MathF.Min(atkC.Health + heal, atkC.MaxHealth);
        }

        return damage;
    }

    /// <summary>
    /// Apply spell damage from attacker to target. Handles shield, omnivamp, grievous wounds.
    /// </summary>
    public static float ApplySpellDamage(float rawDamage, DamageType type, Champion attacker, GameEntity target)
    {
        float damage = CalculateDamage(rawDamage, type, target, attacker);

        if (target is Champion targetChamp)
        {
            damage = targetChamp.ApplyDamage(damage);
        }
        else if (target is IKillable killable)
        {
            killable.Health = MathF.Max(0, killable.Health - damage);
        }

        // Omnivamp from spells
        if (damage > 0 && attacker.Omnivamp > 0)
        {
            float heal = damage * attacker.Omnivamp / 100f;
            if (attacker.GrievousWoundsReduction > 0)
                heal *= (1f - attacker.GrievousWoundsReduction / 100f);
            attacker.Health = MathF.Min(attacker.Health + heal, attacker.MaxHealth);
        }

        return damage;
    }
}
