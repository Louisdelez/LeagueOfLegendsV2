using System;
using System.Collections.Generic;
using System.Linq;
using LoLServer.Core.Game.Entities;

namespace LoLServer.Core.Game.Runes;

/// <summary>
/// Rune system with all 5 trees and their keystones/minor runes.
/// Each champion has a primary tree (keystone + 3 minor) and secondary tree (2 minor).
/// Plus 3 stat shards.
/// </summary>
public static class RuneManager
{
    private static readonly Dictionary<int, RuneData> AllRunes = new();
    private static readonly Dictionary<RuneTree, List<RuneData>> RunesByTree = new();

    static RuneManager()
    {
        foreach (RuneTree tree in Enum.GetValues<RuneTree>())
            RunesByTree[tree] = new List<RuneData>();

        RegisterAllRunes();
    }

    public static RuneData? GetRune(int id) => AllRunes.TryGetValue(id, out var r) ? r : null;
    public static List<RuneData> GetRunesForTree(RuneTree tree) => RunesByTree[tree];
    public static List<RuneData> GetKeystones(RuneTree tree) => RunesByTree[tree].Where(r => r.Slot == RuneSlot.Keystone).ToList();

    /// <summary>
    /// Apply a full rune page to a champion.
    /// </summary>
    public static void ApplyRunePage(Champion champion, RunePage page)
    {
        // Apply stat shards
        foreach (var shard in page.StatShards)
        {
            switch (shard)
            {
                case StatShard.AdaptiveForce: champion.AttackDamage += 5.4f; break;
                case StatShard.AttackSpeed: champion.AttackSpeed *= 1.10f; break;
                case StatShard.AbilityHaste: champion.AbilityHaste += 8; break;
                case StatShard.Armor: champion.Armor += 6; break;
                case StatShard.MagicResist: champion.MagicResist += 8; break;
                case StatShard.Health: champion.MaxHealth += 15; champion.Health += 15; break;
                case StatShard.HealthScaling: champion.MaxHealth += 10; champion.Health += 10; break;
            }
        }

        // Apply rune flat stats
        foreach (var runeId in page.AllRuneIds())
        {
            var rune = GetRune(runeId);
            if (rune == null) continue;

            champion.MaxHealth += rune.BonusHealth;
            champion.Health += rune.BonusHealth;
            champion.AttackDamage += rune.BonusAD;
            champion.Armor += rune.BonusArmor;
            champion.MagicResist += rune.BonusMR;
            champion.MoveSpeed += rune.BonusMS;
        }
    }

    /// <summary>
    /// Process keystone effects on hit/ability/kill.
    /// Returns bonus damage if any.
    /// </summary>
    public static float ProcessKeystoneOnHit(Champion attacker, GameEntity target, float rawDamage, RunePage page)
    {
        var keystone = GetRune(page.Keystone);
        if (keystone == null) return 0;

        return keystone.Id switch
        {
            // Conqueror - stack AD, heal at max stacks
            8010 => rawDamage * 0.03f,

            // Lethal Tempo - bonus AS
            8008 => 0,

            // Fleet Footwork - heal on energized attack
            8021 => MathF.Min(10 + attacker.Level * 5, attacker.MaxHealth * 0.02f),

            // Electrocute - burst damage
            8112 => 30 + attacker.Level * 8 + attacker.AttackDamage * 0.25f,

            // Dark Harvest - execute damage, scales with stacks
            8128 => 20 + attacker.Level * 5,

            // Hail of Blades - no damage, bonus AS
            9923 => 0,

            // Summon Aery - shield/damage
            8214 => 10 + attacker.Level * 4,

            // Arcane Comet - skillshot damage
            8229 => 30 + attacker.Level * 8,

            // Phase Rush - no damage, MS boost
            8230 => 0,

            // Grasp of the Undying - bonus damage + heal
            8437 => attacker.MaxHealth * 0.04f,

            // Aftershock - no damage on hit, delayed burst
            8439 => 0,

            // Guardian - shield ally
            8465 => 0,

            // Press the Attack - bonus damage after 3 hits
            8005 => 40 + attacker.Level * 10,

            _ => 0
        };
    }

    private static void Register(int id, string name, RuneTree tree, RuneSlot slot,
        float hp = 0, float ad = 0, float armor = 0, float mr = 0, float ms = 0)
    {
        var rune = new RuneData
        {
            Id = id, Name = name, Tree = tree, Slot = slot,
            BonusHealth = hp, BonusAD = ad, BonusArmor = armor, BonusMR = mr, BonusMS = ms
        };
        AllRunes[id] = rune;
        RunesByTree[tree].Add(rune);
    }

    private static void RegisterAllRunes()
    {
        // === PRECISION ===
        Register(8005, "Press the Attack", RuneTree.Precision, RuneSlot.Keystone);
        Register(8008, "Lethal Tempo", RuneTree.Precision, RuneSlot.Keystone);
        Register(8010, "Conqueror", RuneTree.Precision, RuneSlot.Keystone);
        Register(8021, "Fleet Footwork", RuneTree.Precision, RuneSlot.Keystone);

        Register(9101, "Overheal", RuneTree.Precision, RuneSlot.Row1);
        Register(9111, "Triumph", RuneTree.Precision, RuneSlot.Row1);
        Register(8009, "Presence of Mind", RuneTree.Precision, RuneSlot.Row1);

        Register(9104, "Legend: Alacrity", RuneTree.Precision, RuneSlot.Row2);
        Register(9105, "Legend: Tenacity", RuneTree.Precision, RuneSlot.Row2);
        Register(9103, "Legend: Bloodline", RuneTree.Precision, RuneSlot.Row2);

        Register(8014, "Coup de Grace", RuneTree.Precision, RuneSlot.Row3);
        Register(8017, "Cut Down", RuneTree.Precision, RuneSlot.Row3);
        Register(8299, "Last Stand", RuneTree.Precision, RuneSlot.Row3);

        // === DOMINATION ===
        Register(8112, "Electrocute", RuneTree.Domination, RuneSlot.Keystone);
        Register(8124, "Predator", RuneTree.Domination, RuneSlot.Keystone, ms: 10);
        Register(8128, "Dark Harvest", RuneTree.Domination, RuneSlot.Keystone);
        Register(9923, "Hail of Blades", RuneTree.Domination, RuneSlot.Keystone);

        Register(8126, "Cheap Shot", RuneTree.Domination, RuneSlot.Row1);
        Register(8139, "Taste of Blood", RuneTree.Domination, RuneSlot.Row1);
        Register(8143, "Sudden Impact", RuneTree.Domination, RuneSlot.Row1);

        Register(8136, "Zombie Ward", RuneTree.Domination, RuneSlot.Row2);
        Register(8120, "Ghost Poro", RuneTree.Domination, RuneSlot.Row2);
        Register(8138, "Eyeball Collection", RuneTree.Domination, RuneSlot.Row2, ad: 1.2f);

        Register(8135, "Treasure Hunter", RuneTree.Domination, RuneSlot.Row3);
        Register(8134, "Ingenious Hunter", RuneTree.Domination, RuneSlot.Row3);
        Register(8105, "Relentless Hunter", RuneTree.Domination, RuneSlot.Row3, ms: 5);
        Register(8106, "Ultimate Hunter", RuneTree.Domination, RuneSlot.Row3);

        // === SORCERY ===
        Register(8214, "Summon Aery", RuneTree.Sorcery, RuneSlot.Keystone);
        Register(8229, "Arcane Comet", RuneTree.Sorcery, RuneSlot.Keystone);
        Register(8230, "Phase Rush", RuneTree.Sorcery, RuneSlot.Keystone);

        Register(8224, "Nullifying Orb", RuneTree.Sorcery, RuneSlot.Row1);
        Register(8226, "Manaflow Band", RuneTree.Sorcery, RuneSlot.Row1);
        Register(8275, "Nimbus Cloak", RuneTree.Sorcery, RuneSlot.Row1);

        Register(8210, "Transcendence", RuneTree.Sorcery, RuneSlot.Row2);
        Register(8234, "Celerity", RuneTree.Sorcery, RuneSlot.Row2, ms: 1);
        Register(8233, "Absolute Focus", RuneTree.Sorcery, RuneSlot.Row2, ad: 1.8f);

        Register(8237, "Scorch", RuneTree.Sorcery, RuneSlot.Row3);
        Register(8232, "Waterwalking", RuneTree.Sorcery, RuneSlot.Row3, ms: 3, ad: 3);
        Register(8236, "Gathering Storm", RuneTree.Sorcery, RuneSlot.Row3);

        // === RESOLVE ===
        Register(8437, "Grasp of the Undying", RuneTree.Resolve, RuneSlot.Keystone);
        Register(8439, "Aftershock", RuneTree.Resolve, RuneSlot.Keystone);
        Register(8465, "Guardian", RuneTree.Resolve, RuneSlot.Keystone);

        Register(8446, "Demolish", RuneTree.Resolve, RuneSlot.Row1);
        Register(8463, "Font of Life", RuneTree.Resolve, RuneSlot.Row1);
        Register(8401, "Shield Bash", RuneTree.Resolve, RuneSlot.Row1);

        Register(8429, "Conditioning", RuneTree.Resolve, RuneSlot.Row2, armor: 9, mr: 9);
        Register(8444, "Second Wind", RuneTree.Resolve, RuneSlot.Row2);
        Register(8473, "Bone Plating", RuneTree.Resolve, RuneSlot.Row2);

        Register(8451, "Overgrowth", RuneTree.Resolve, RuneSlot.Row3, hp: 15);
        Register(8453, "Revitalize", RuneTree.Resolve, RuneSlot.Row3);
        Register(8242, "Unflinching", RuneTree.Resolve, RuneSlot.Row3);

        // === INSPIRATION ===
        Register(8351, "Glacial Augment", RuneTree.Inspiration, RuneSlot.Keystone);
        Register(8360, "Unsealed Spellbook", RuneTree.Inspiration, RuneSlot.Keystone);
        Register(8369, "First Strike", RuneTree.Inspiration, RuneSlot.Keystone);

        Register(8306, "Hextech Flashtraption", RuneTree.Inspiration, RuneSlot.Row1);
        Register(8304, "Magical Footwear", RuneTree.Inspiration, RuneSlot.Row1, ms: 10);
        Register(8313, "Triple Tonic", RuneTree.Inspiration, RuneSlot.Row1);

        Register(8321, "Future's Market", RuneTree.Inspiration, RuneSlot.Row2);
        Register(8316, "Minion Dematerializer", RuneTree.Inspiration, RuneSlot.Row2);
        Register(8345, "Biscuit Delivery", RuneTree.Inspiration, RuneSlot.Row2);

        Register(8347, "Cosmic Insight", RuneTree.Inspiration, RuneSlot.Row3);
        Register(8410, "Approach Velocity", RuneTree.Inspiration, RuneSlot.Row3, ms: 3);
        Register(8352, "Time Warp Tonic", RuneTree.Inspiration, RuneSlot.Row3);
    }
}

public class RuneData
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public RuneTree Tree { get; set; }
    public RuneSlot Slot { get; set; }
    public float BonusHealth { get; set; }
    public float BonusAD { get; set; }
    public float BonusArmor { get; set; }
    public float BonusMR { get; set; }
    public float BonusMS { get; set; }
}

public class RunePage
{
    public RuneTree PrimaryTree { get; set; }
    public int Keystone { get; set; }
    public int PrimaryRow1 { get; set; }
    public int PrimaryRow2 { get; set; }
    public int PrimaryRow3 { get; set; }

    public RuneTree SecondaryTree { get; set; }
    public int SecondaryRune1 { get; set; }
    public int SecondaryRune2 { get; set; }

    public StatShard[] StatShards { get; set; } = new StatShard[3]
    {
        StatShard.AdaptiveForce,
        StatShard.AdaptiveForce,
        StatShard.Health
    };

    public IEnumerable<int> AllRuneIds()
    {
        yield return Keystone;
        yield return PrimaryRow1;
        yield return PrimaryRow2;
        yield return PrimaryRow3;
        yield return SecondaryRune1;
        yield return SecondaryRune2;
    }

    /// <summary>
    /// Default ADC rune page (Lethal Tempo / Precision + Domination)
    /// </summary>
    public static RunePage DefaultADC => new()
    {
        PrimaryTree = RuneTree.Precision,
        Keystone = 8008, // Lethal Tempo
        PrimaryRow1 = 9111, // Triumph
        PrimaryRow2 = 9104, // Legend: Alacrity
        PrimaryRow3 = 8014, // Coup de Grace
        SecondaryTree = RuneTree.Domination,
        SecondaryRune1 = 8139, // Taste of Blood
        SecondaryRune2 = 8135, // Treasure Hunter
        StatShards = new[] { StatShard.AttackSpeed, StatShard.AdaptiveForce, StatShard.Health }
    };

    /// <summary>
    /// Default AP mage rune page (Arcane Comet / Sorcery + Inspiration)
    /// </summary>
    public static RunePage DefaultMage => new()
    {
        PrimaryTree = RuneTree.Sorcery,
        Keystone = 8229, // Arcane Comet
        PrimaryRow1 = 8226, // Manaflow Band
        PrimaryRow2 = 8210, // Transcendence
        PrimaryRow3 = 8237, // Scorch
        SecondaryTree = RuneTree.Inspiration,
        SecondaryRune1 = 8345, // Biscuit Delivery
        SecondaryRune2 = 8347, // Cosmic Insight
        StatShards = new[] { StatShard.AdaptiveForce, StatShard.AdaptiveForce, StatShard.Health }
    };

    /// <summary>
    /// Default tank rune page (Grasp / Resolve + Precision)
    /// </summary>
    public static RunePage DefaultTank => new()
    {
        PrimaryTree = RuneTree.Resolve,
        Keystone = 8437, // Grasp
        PrimaryRow1 = 8446, // Demolish
        PrimaryRow2 = 8429, // Conditioning
        PrimaryRow3 = 8451, // Overgrowth
        SecondaryTree = RuneTree.Precision,
        SecondaryRune1 = 9111, // Triumph
        SecondaryRune2 = 9105, // Legend: Tenacity
        StatShards = new[] { StatShard.AttackSpeed, StatShard.Armor, StatShard.Health }
    };

    /// <summary>
    /// Default assassin rune page (Electrocute / Domination + Sorcery)
    /// </summary>
    public static RunePage DefaultAssassin => new()
    {
        PrimaryTree = RuneTree.Domination,
        Keystone = 8112, // Electrocute
        PrimaryRow1 = 8143, // Sudden Impact
        PrimaryRow2 = 8138, // Eyeball Collection
        PrimaryRow3 = 8106, // Ultimate Hunter
        SecondaryTree = RuneTree.Sorcery,
        SecondaryRune1 = 8210, // Transcendence
        SecondaryRune2 = 8237, // Scorch
        StatShards = new[] { StatShard.AdaptiveForce, StatShard.AdaptiveForce, StatShard.Armor }
    };
}

public enum RuneTree { Precision, Domination, Sorcery, Resolve, Inspiration }
public enum RuneSlot { Keystone, Row1, Row2, Row3 }
public enum StatShard { AdaptiveForce, AttackSpeed, AbilityHaste, Armor, MagicResist, Health, HealthScaling }
