using System;
using System.Collections.Generic;
using LoLServer.Core.Config;
using LoLServer.Core.Game.Combat;
using LoLServer.Core.Game.Entities;

namespace LoLServer.Core.Game.Spells;

/// <summary>
/// Manages champion spells (Q/W/E/R) and summoner spells.
/// Contains base data for popular champions.
/// </summary>
public static class SpellManager
{
    private static readonly Dictionary<string, ChampionSpellKit> ChampionSpells = new();
    private static readonly Dictionary<string, SummonerSpellData> SummonerSpells = new();

    static SpellManager()
    {
        RegisterSummonerSpells();
        RegisterChampionSpells();
    }

    public static ChampionSpellKit? GetSpellKit(string championName)
        => ChampionSpells.TryGetValue(championName, out var kit) ? kit : null;

    public static SummonerSpellData? GetSummonerSpell(string name)
        => SummonerSpells.TryGetValue(name, out var spell) ? spell : null;

    /// <summary>
    /// Cast a champion spell. Returns true if the spell was cast successfully.
    /// </summary>
    public static CastResult CastSpell(Champion caster, int spellSlot, Vector3 targetPos, GameEntity? targetEntity, GameLoop game)
    {
        if (spellSlot < 0 || spellSlot >= 4) return new CastResult(false, "Invalid slot");

        var ability = caster.Abilities[spellSlot];
        if (ability.Level == 0) return new CastResult(false, "Spell not learned");
        if (ability.CurrentCooldown > 0) return new CastResult(false, $"On cooldown ({ability.CurrentCooldown:F1}s)");
        if (caster.Mana < ability.ManaCost) return new CastResult(false, "Not enough mana");

        var kit = GetSpellKit(caster.ChampionName);
        if (kit == null) return new CastResult(false, "No spell data for champion");

        var spellData = spellSlot switch
        {
            0 => kit.Q, 1 => kit.W, 2 => kit.E, 3 => kit.R,
            _ => null
        };
        if (spellData == null) return new CastResult(false, "No spell data");

        // Deduct mana and set cooldown
        caster.Mana -= ability.ManaCost;
        ability.CurrentCooldown = spellData.Cooldowns[Math.Min(ability.Level - 1, spellData.Cooldowns.Length - 1)];

        // Apply damage
        float damage = spellData.BaseDamage[Math.Min(ability.Level - 1, spellData.BaseDamage.Length - 1)];
        damage += spellData.AdRatio * caster.AttackDamage;
        // AP scaling would use a champion.AbilityPower stat

        if (targetEntity != null && targetEntity.Team != caster.Team)
        {
            float actualDamage = DamageCalculator.CalculateDamage(damage, spellData.DamageType, targetEntity);
            if (targetEntity is IKillable killable)
            {
                killable.Health = MathF.Max(0, killable.Health - actualDamage);
            }

            return new CastResult(true, $"{caster.ChampionName} {spellData.Name} -> {actualDamage:F0} damage");
        }

        return new CastResult(true, $"{caster.ChampionName} cast {spellData.Name}");
    }

    /// <summary>
    /// Cast a summoner spell (Flash, Ignite, etc.)
    /// </summary>
    public static CastResult CastSummonerSpell(Champion caster, string spellName, Vector3 targetPos, GameEntity? target, GameLoop game)
    {
        var spell = GetSummonerSpell(spellName);
        if (spell == null) return new CastResult(false, "Unknown summoner spell");

        switch (spellName)
        {
            case "SummonerFlash":
                // Teleport 400 units toward target position
                var dir = caster.Position.DirectionTo(targetPos);
                caster.Position = new Vector3(
                    caster.Position.X + dir.X * 400,
                    caster.Position.Y,
                    caster.Position.Z + dir.Z * 400
                );
                return new CastResult(true, "Flash!");

            case "SummonerIgnite":
                if (target is Champion targetChamp && target.Team != caster.Team)
                {
                    // 70-410 true damage over 5 seconds (based on level)
                    float igniteDmg = 50 + 20 * caster.Level;
                    targetChamp.Health -= igniteDmg; // Simplified: instant instead of DoT
                    return new CastResult(true, $"Ignite! {igniteDmg:F0} true damage");
                }
                return new CastResult(false, "No valid target");

            case "SummonerHeal":
                float healAmount = 80 + 15 * caster.Level;
                caster.Health = MathF.Min(caster.Health + healAmount, caster.MaxHealth);
                caster.MoveSpeed += 30; // Brief MS boost (simplified)
                return new CastResult(true, $"Heal! +{healAmount:F0} HP");

            case "SummonerBarrier":
                // Shield for 105-411 (simplified as temp HP)
                float shield = 95 + 20 * caster.Level;
                caster.Health = MathF.Min(caster.Health + shield, caster.MaxHealth + shield);
                return new CastResult(true, $"Barrier! +{shield:F0} shield");

            case "SummonerTeleport":
                if (target is Turret turret && turret.Team == caster.Team)
                {
                    caster.Position = turret.Position;
                    return new CastResult(true, "Teleport!");
                }
                return new CastResult(false, "Must target allied turret");

            case "SummonerSmite":
                if (target is Entities.Minion || target is JungleMonster)
                {
                    if (target is IKillable k)
                        k.Health -= 900; // Smite damage
                    return new CastResult(true, "Smite! 900 damage");
                }
                return new CastResult(false, "Must target monster/minion");

            case "SummonerExhaust":
                if (target is Champion exhaustTarget && target.Team != caster.Team)
                {
                    exhaustTarget.MoveSpeed *= 0.7f; // 30% slow
                    exhaustTarget.AttackDamage *= 0.6f; // 40% damage reduction
                    return new CastResult(true, "Exhaust!");
                }
                return new CastResult(false, "No valid target");

            default:
                return new CastResult(false, $"Unimplemented: {spellName}");
        }
    }

    // ============== SUMMONER SPELLS ==============

    private static void RegisterSummonerSpells()
    {
        SummonerSpells["SummonerFlash"] = new("Flash", 300);
        SummonerSpells["SummonerIgnite"] = new("Ignite", 180);
        SummonerSpells["SummonerHeal"] = new("Heal", 240);
        SummonerSpells["SummonerBarrier"] = new("Barrier", 180);
        SummonerSpells["SummonerTeleport"] = new("Teleport", 360);
        SummonerSpells["SummonerSmite"] = new("Smite", 15);
        SummonerSpells["SummonerExhaust"] = new("Exhaust", 210);
        SummonerSpells["SummonerCleanse"] = new("Cleanse", 210);
        SummonerSpells["SummonerGhost"] = new("Ghost", 210);
    }

    // ============== CHAMPION SPELLS ==============

    private static void RegisterChampionSpells()
    {
        // --- EZREAL ---
        ChampionSpells["Ezreal"] = new ChampionSpellKit
        {
            Q = new SpellData("Mystic Shot", DamageType.Physical, new[] { 20f, 45f, 70f, 95f, 120f }, 1.3f, 0,
                new[] { 5.5f, 5.25f, 5f, 4.75f, 4.5f }, 1150, 28),
            W = new SpellData("Essence Flux", DamageType.Magic, new[] { 80f, 135f, 190f, 245f, 300f }, 0.6f, 0.7f,
                new[] { 12f, 12f, 12f, 12f, 12f }, 1150, 50),
            E = new SpellData("Arcane Shift", DamageType.Magic, new[] { 80f, 130f, 180f, 230f, 280f }, 0.5f, 0.75f,
                new[] { 28f, 25f, 22f, 19f, 16f }, 475, 90),
            R = new SpellData("Trueshot Barrage", DamageType.Magic, new[] { 350f, 500f, 650f }, 1.0f, 0.9f,
                new[] { 120f, 105f, 90f }, 99999, 100)
        };

        // --- LUX ---
        ChampionSpells["Lux"] = new ChampionSpellKit
        {
            Q = new SpellData("Light Binding", DamageType.Magic, new[] { 80f, 120f, 160f, 200f, 240f }, 0, 0.6f,
                new[] { 11f, 10.5f, 10f, 9.5f, 9f }, 1175, 50),
            W = new SpellData("Prismatic Barrier", DamageType.Magic, new[] { 45f, 65f, 85f, 105f, 125f }, 0, 0.35f,
                new[] { 14f, 13f, 12f, 11f, 10f }, 1075, 60), // Shield, not damage
            E = new SpellData("Lucent Singularity", DamageType.Magic, new[] { 60f, 110f, 160f, 210f, 260f }, 0, 0.65f,
                new[] { 10f, 10f, 10f, 10f, 10f }, 1100, 70),
            R = new SpellData("Final Spark", DamageType.Magic, new[] { 300f, 400f, 500f }, 0, 1.0f,
                new[] { 80f, 60f, 40f }, 3400, 100)
        };

        // --- JINX ---
        ChampionSpells["Jinx"] = new ChampionSpellKit
        {
            Q = new SpellData("Switcheroo!", DamageType.Physical, new[] { 10f, 17f, 24f, 31f, 38f }, 1.1f, 0,
                new[] { 0.9f, 0.9f, 0.9f, 0.9f, 0.9f }, 700, 20), // Toggle
            W = new SpellData("Zap!", DamageType.Physical, new[] { 10f, 60f, 110f, 160f, 210f }, 1.6f, 0,
                new[] { 8f, 7f, 6f, 5f, 4f }, 1450, 50),
            E = new SpellData("Flame Chompers!", DamageType.Magic, new[] { 70f, 120f, 170f, 220f, 270f }, 0, 1.0f,
                new[] { 24f, 20.5f, 17f, 13.5f, 10f }, 925, 70),
            R = new SpellData("Super Mega Death Rocket!", DamageType.Physical, new[] { 250f, 400f, 550f }, 1.5f, 0.25f,
                new[] { 90f, 75f, 60f }, 99999, 100)
        };

        // --- YASUO ---
        ChampionSpells["Yasuo"] = new ChampionSpellKit
        {
            Q = new SpellData("Steel Tempest", DamageType.Physical, new[] { 20f, 45f, 70f, 95f, 120f }, 1.05f, 0,
                new[] { 4f, 3.67f, 3.33f, 3f, 2.67f }, 475, 0),
            W = new SpellData("Wind Wall", DamageType.Physical, new[] { 0f, 0f, 0f, 0f, 0f }, 0, 0,
                new[] { 30f, 27f, 24f, 21f, 18f }, 400, 0), // No damage, blocks projectiles
            E = new SpellData("Sweeping Blade", DamageType.Magic, new[] { 60f, 70f, 80f, 90f, 100f }, 0, 0.2f,
                new[] { 0.5f, 0.4f, 0.3f, 0.2f, 0.1f }, 475, 0),
            R = new SpellData("Last Breath", DamageType.Physical, new[] { 200f, 350f, 500f }, 1.5f, 0,
                new[] { 80f, 55f, 30f }, 1400, 0)
        };

        // --- GAREN ---
        ChampionSpells["Garen"] = new ChampionSpellKit
        {
            Q = new SpellData("Decisive Strike", DamageType.Physical, new[] { 30f, 60f, 90f, 120f, 150f }, 0.5f, 0,
                new[] { 8f, 8f, 8f, 8f, 8f }, 300, 0),
            W = new SpellData("Courage", DamageType.Physical, new[] { 0f, 0f, 0f, 0f, 0f }, 0, 0,
                new[] { 23f, 21f, 19f, 17f, 15f }, 0, 0), // Shield
            E = new SpellData("Judgment", DamageType.Physical, new[] { 14f, 18f, 22f, 26f, 30f }, 0.36f, 0,
                new[] { 9f, 9f, 9f, 9f, 9f }, 325, 0), // Per spin
            R = new SpellData("Demacian Justice", DamageType.True, new[] { 150f, 300f, 450f }, 0, 0,
                new[] { 120f, 100f, 80f }, 400, 0) // +%missing HP
        };

        // --- DARIUS ---
        ChampionSpells["Darius"] = new ChampionSpellKit
        {
            Q = new SpellData("Decimate", DamageType.Physical, new[] { 50f, 80f, 110f, 140f, 170f }, 1.0f, 0,
                new[] { 9f, 8f, 7f, 6f, 5f }, 425, 30),
            W = new SpellData("Crippling Strike", DamageType.Physical, new[] { 0f, 0f, 0f, 0f, 0f }, 1.4f, 0,
                new[] { 7f, 6.5f, 6f, 5.5f, 5f }, 300, 30), // Auto reset
            E = new SpellData("Apprehend", DamageType.Physical, new[] { 0f, 0f, 0f, 0f, 0f }, 0, 0,
                new[] { 24f, 21f, 18f, 15f, 12f }, 535, 45), // Pull
            R = new SpellData("Noxian Guillotine", DamageType.True, new[] { 100f, 200f, 300f }, 0.75f, 0,
                new[] { 120f, 100f, 80f }, 460, 100)
        };

        // --- AHRI ---
        ChampionSpells["Ahri"] = new ChampionSpellKit
        {
            Q = new SpellData("Orb of Deception", DamageType.Magic, new[] { 40f, 65f, 90f, 115f, 140f }, 0, 0.45f,
                new[] { 7f, 7f, 7f, 7f, 7f }, 880, 60),
            W = new SpellData("Fox-Fire", DamageType.Magic, new[] { 60f, 85f, 110f, 135f, 160f }, 0, 0.48f,
                new[] { 9f, 8f, 7f, 6f, 5f }, 725, 30),
            E = new SpellData("Charm", DamageType.Magic, new[] { 80f, 110f, 140f, 170f, 200f }, 0, 0.6f,
                new[] { 12f, 12f, 12f, 12f, 12f }, 975, 70),
            R = new SpellData("Spirit Rush", DamageType.Magic, new[] { 60f, 90f, 120f }, 0, 0.35f,
                new[] { 130f, 105f, 80f }, 450, 0) // 3 dashes
        };

        // --- MISS FORTUNE ---
        ChampionSpells["MissFortune"] = new ChampionSpellKit
        {
            Q = new SpellData("Double Up", DamageType.Physical, new[] { 20f, 40f, 60f, 80f, 100f }, 1.0f, 0.35f,
                new[] { 7f, 6f, 5f, 4f, 3f }, 650, 43),
            W = new SpellData("Strut", DamageType.Physical, new[] { 0f, 0f, 0f, 0f, 0f }, 0, 0,
                new[] { 12f, 12f, 12f, 12f, 12f }, 0, 30), // AS steroid
            E = new SpellData("Make It Rain", DamageType.Magic, new[] { 70f, 100f, 130f, 160f, 190f }, 0, 0.8f,
                new[] { 18f, 16f, 14f, 12f, 10f }, 1000, 80),
            R = new SpellData("Bullet Time", DamageType.Physical, new[] { 75f, 100f, 125f }, 0.75f, 0.2f,
                new[] { 120f, 110f, 100f }, 1400, 100) // Per wave, 12-18 waves
        };
    }
}

public class ChampionSpellKit
{
    public SpellData Q { get; set; } = null!;
    public SpellData W { get; set; } = null!;
    public SpellData E { get; set; } = null!;
    public SpellData R { get; set; } = null!;
}

public class SpellData
{
    public string Name { get; set; }
    public DamageType DamageType { get; set; }
    public float[] BaseDamage { get; set; }  // Per rank (1-5)
    public float AdRatio { get; set; }
    public float ApRatio { get; set; }
    public float[] Cooldowns { get; set; }   // Per rank
    public float Range { get; set; }
    public float ManaCost { get; set; }

    public SpellData(string name, DamageType type, float[] baseDmg, float adRatio, float apRatio,
        float[] cooldowns, float range, float mana)
    {
        Name = name; DamageType = type; BaseDamage = baseDmg;
        AdRatio = adRatio; ApRatio = apRatio; Cooldowns = cooldowns;
        Range = range; ManaCost = mana;
    }
}

public class SummonerSpellData
{
    public string Name { get; set; }
    public float Cooldown { get; set; }

    public SummonerSpellData(string name, float cooldown)
    {
        Name = name; Cooldown = cooldown;
    }
}

public record CastResult(bool Success, string Message);

/// <summary>
/// Jungle monster entity (for Smite targeting).
/// </summary>
public class JungleMonster : GameEntity, IKillable
{
    public float Health { get; set; }
    public float MaxHealth { get; set; }
}
