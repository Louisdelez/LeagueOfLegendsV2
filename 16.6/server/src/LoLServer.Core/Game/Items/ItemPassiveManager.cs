using System;
using System.Linq;
using LoLServer.Core.Game.Buffs;
using LoLServer.Core.Game.Combat;
using LoLServer.Core.Game.Entities;

namespace LoLServer.Core.Game.Items;

/// <summary>
/// Handles item passive/active effects that trigger on events:
/// on-hit, on-spell, on-kill, per-tick, etc.
/// </summary>
public static class ItemPassiveManager
{
    /// <summary>
    /// Process on-hit item passives when a champion auto-attacks.
    /// Returns bonus damage to apply.
    /// </summary>
    public static float ProcessOnHit(Champion attacker, GameEntity target)
    {
        float bonusDamage = 0;

        for (int i = 0; i < 6; i++)
        {
            int itemId = attacker.Items[i];
            if (itemId == 0) continue;

            switch (itemId)
            {
                // === SPELLBLADE items (Sheen / Lich Bane / Trinity Force) ===
                // Simplified: always proc (real game has 1.5s cooldown after spell cast)

                case 3100: // Lich Bane - 75% AP + 50% base AD magic damage
                    bonusDamage += attacker.AbilityPower * 0.75f + attacker.AttackDamage * 0.5f;
                    break;

                case 3078: // Trinity Force - 200% base AD
                    bonusDamage += attacker.AttackDamage * 2.0f;
                    break;

                // === BLADE OF THE RUINED KING ===
                case 3153: // BotRK - 10% target current HP on-hit (melee) / 6% (ranged)
                    if (target is IKillable borkTarget)
                    {
                        float borkPct = attacker.AttackRange <= 300 ? 0.10f : 0.06f;
                        bonusDamage += borkTarget.Health * borkPct;
                    }
                    break;

                // === KRAKEN SLAYER ===
                case 6672: // Kraken Slayer - every 3rd attack deals bonus true damage
                    // Simplified: average damage per hit (true dmg / 3)
                    bonusDamage += (35 + attacker.AttackDamage * 0.1f) / 3f;
                    break;

                // === WIT'S END ===
                case 3091: // Wit's End - 15-80 magic damage on-hit (scales with level)
                    bonusDamage += 15 + (80 - 15) * (attacker.Level - 1) / 17f;
                    break;

                // === NASHOR'S TOOTH ===
                case 3115: // Nashor's Tooth - 15 + 20% AP magic damage on-hit
                    bonusDamage += 15 + attacker.AbilityPower * 0.2f;
                    break;

                // === RECURVE BOW ===
                case 1043: // Recurve Bow - 15 on-hit
                    bonusDamage += 15;
                    break;
            }
        }

        return bonusDamage;
    }

    /// <summary>
    /// Process on-being-hit item passives (Thornmail, Sunfire, etc.)
    /// Called when a champion takes damage from an auto-attack.
    /// </summary>
    public static void ProcessOnBeingHit(Champion defender, GameEntity attacker, float damageDealt)
    {
        for (int i = 0; i < 6; i++)
        {
            int itemId = defender.Items[i];
            if (itemId == 0) continue;

            switch (itemId)
            {
                case 3075: // Thornmail - reflect 10 + 10% bonus armor as magic damage + grievous wounds
                    if (attacker is IKillable thornTarget)
                    {
                        float reflectDmg = 10 + defender.Armor * 0.1f;
                        thornTarget.Health = MathF.Max(0, thornTarget.Health - reflectDmg);
                    }
                    // Apply Grievous Wounds to attacker
                    if (attacker is Champion atkChamp)
                    {
                        atkChamp.GrievousWoundsReduction = 40;
                    }
                    break;

                case 3076: // Bramble Vest - reflect 3 + 10% bonus armor
                    if (attacker is IKillable brambleTarget)
                    {
                        float reflectDmg = 3 + defender.Armor * 0.1f;
                        brambleTarget.Health = MathF.Max(0, brambleTarget.Health - reflectDmg);
                    }
                    if (attacker is Champion atkChamp2)
                    {
                        atkChamp2.GrievousWoundsReduction = 25;
                    }
                    break;

                case 3143: // Randuin's Omen - reduce incoming crit damage by 20% (already built into damage calc)
                    break;
            }
        }
    }

    /// <summary>
    /// Process on-spell-cast item passives.
    /// Called when a champion casts a spell.
    /// </summary>
    public static float ProcessOnSpellCast(Champion caster, GameEntity? target)
    {
        float bonusDamage = 0;

        for (int i = 0; i < 6; i++)
        {
            int itemId = caster.Items[i];
            if (itemId == 0) continue;

            switch (itemId)
            {
                case 3165: // Morellonomicon - apply Grievous Wounds on magic damage
                    if (target is Champion morelloTarget)
                    {
                        morelloTarget.GrievousWoundsReduction = 40;
                    }
                    break;

                case 3116: // Rylai's Crystal Scepter - slow on spell damage
                    if (target is Champion rylaiTarget)
                    {
                        rylaiTarget.Buffs.AddBuff(BuffManager.CreateSlowBuff(30, 1), rylaiTarget);
                    }
                    break;
            }
        }

        return bonusDamage;
    }

    /// <summary>
    /// Process on-kill item passives.
    /// Called when a champion gets a kill or assist.
    /// </summary>
    public static void ProcessOnKill(Champion killer, GameEntity victim)
    {
        for (int i = 0; i < 6; i++)
        {
            int itemId = killer.Items[i];
            if (itemId == 0) continue;

            switch (itemId)
            {
                case 6676: // The Collector - execute targets below 5% HP
                    // Already dead at this point, but bonus gold
                    killer.Gold += 25;
                    break;

                case 3072: // Bloodthirster - on kill, overheal to shield
                    killer.Shield = MathF.Min(killer.Shield + 50, killer.MaxHealth * 0.15f);
                    break;
            }
        }
    }

    /// <summary>
    /// Process per-tick item passives (Sunfire, Warmog's, etc.)
    /// Called every game tick.
    /// </summary>
    public static void ProcessPerTick(Champion champion, float deltaTime, GameLoop game)
    {
        for (int i = 0; i < 6; i++)
        {
            int itemId = champion.Items[i];
            if (itemId == 0) continue;

            switch (itemId)
            {
                case 3068: // Sunfire Aegis - immolate: 15 + 1% bonus HP/s to nearby enemies
                    float immoleDmg = (15 + champion.MaxHealth * 0.01f) * deltaTime;
                    foreach (var entity in game.Entities)
                    {
                        if (entity.Team == champion.Team || !entity.IsTargetable) continue;
                        if (entity is IKillable k && k.Health <= 0) continue;
                        if (champion.Position.Distance2D(entity.Position) <= 325)
                        {
                            if (entity is IKillable target)
                                target.Health = MathF.Max(0, target.Health - immoleDmg);
                        }
                    }
                    break;

                case 3083: // Warmog's Armor - regen 2.5% max HP/s out of combat
                    // Simplified: always active if above 1100 bonus HP
                    if (champion.MaxHealth >= 1700) // Base ~600 + 1100 bonus
                    {
                        float warmogHeal = champion.MaxHealth * 0.025f * deltaTime;
                        if (champion.GrievousWoundsReduction > 0)
                            warmogHeal *= (1f - champion.GrievousWoundsReduction / 100f);
                        champion.Health = MathF.Min(champion.Health + warmogHeal, champion.MaxHealth);
                    }
                    break;

                case 3742: // Dead Man's Plate - build momentum while moving
                    // Simplified: +5% MS while at max stacks
                    break;

                case 3065: // Spirit Visage - +25% healing (applied as regen boost)
                    // Already integrated into base regen stats
                    break;
            }
        }

        // Rabadon's Deathcap bonus: +35% total AP
        if (champion.Items.Contains(3089))
        {
            // This is tricky since it's multiplicative. We handle it by checking
            // if the bonus is already applied via a flag approach.
            // For simplicity, the +35% is already baked into the high base AP of Rabadon's.
        }
    }

    /// <summary>
    /// Check if champion has execute threshold from items (The Collector: < 5% HP).
    /// </summary>
    public static bool ShouldExecute(Champion attacker, GameEntity target)
    {
        if (target is not IKillable killable) return false;

        for (int i = 0; i < 6; i++)
        {
            int itemId = attacker.Items[i];
            if (itemId == 0) continue;

            switch (itemId)
            {
                case 6676: // The Collector - execute below 5%
                    if (killable.Health > 0 && killable.Health / killable.MaxHealth < 0.05f)
                        return true;
                    break;
            }
        }

        return false;
    }

    /// <summary>
    /// Get total lifesteal from items.
    /// </summary>
    public static float GetLifestealFromItems(Champion champion)
    {
        float lifesteal = 0;

        for (int i = 0; i < 6; i++)
        {
            int itemId = champion.Items[i];
            switch (itemId)
            {
                case 3072: lifesteal += 20; break; // Bloodthirster
                case 3153: lifesteal += 12; break; // BotRK
                case 6673: lifesteal += 15; break; // Immortal Shieldbow
            }
        }

        return lifesteal;
    }

    /// <summary>
    /// Get omnivamp from items.
    /// </summary>
    public static float GetOmnivampFromItems(Champion champion)
    {
        float omnivamp = 0;

        for (int i = 0; i < 6; i++)
        {
            int itemId = champion.Items[i];
            switch (itemId)
            {
                case 3074: omnivamp += 10; break; // Ravenous Hydra
            }
        }

        return omnivamp;
    }
}
