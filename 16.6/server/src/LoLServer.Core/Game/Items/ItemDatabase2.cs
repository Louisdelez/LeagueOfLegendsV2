using System;

namespace LoLServer.Core.Game.Items;

/// <summary>
/// Extended item database: additional items not in base ItemManager.
/// Trinity Force, Wit's End, Nashor's Tooth, Guardian Angel, Zeal items,
/// Mythics, Legendaries, Enchanter items, etc.
/// </summary>
public static class ItemDatabase2
{
    /// <summary>
    /// Register all additional items. Call once at startup.
    /// </summary>
    public static void RegisterAll(System.Collections.Generic.Dictionary<int, ItemData> items)
    {
        // === ADDITIONAL COMPONENTS ===
        R(items, 3086, "Zeal", ItemCategory.Component, 1050, new ItemStats { AttackSpeedPercent = 18, CritChancePercent = 15, MoveSpeed = 7 });
        R(items, 3057, "Sheen", ItemCategory.Component, 700, new ItemStats { AbilityHaste = 10 });
        R(items, 3108, "Fiendish Codex", ItemCategory.Component, 900, new ItemStats { AbilityPower = 35, AbilityHaste = 10 });
        R(items, 3113, "Aether Wisp", ItemCategory.Component, 850, new ItemStats { AbilityPower = 30, MoveSpeed = 5 });
        R(items, 3114, "Forbidden Idol", ItemCategory.Component, 800, new ItemStats { ManaRegen = 5 }); // +10% heal/shield
        R(items, 3133, "Caulfield's Warhammer", ItemCategory.Component, 1100, new ItemStats { AttackDamage = 25, AbilityHaste = 10 });
        R(items, 3066, "Winged Moonplate", ItemCategory.Component, 800, new ItemStats { Health = 150, MoveSpeed = 5 });
        R(items, 1031, "Chain Vest", ItemCategory.Component, 800, new ItemStats { Armor = 40 });
        R(items, 1057, "Negatron Cloak", ItemCategory.Component, 900, new ItemStats { MagicResist = 50 });
        R(items, 3077, "Tiamat", ItemCategory.Component, 1200, new ItemStats { AttackDamage = 25 }); // cleave passive
        R(items, 6029, "Ironspike Whip", ItemCategory.Component, 1100, new ItemStats { AttackDamage = 30 });

        // === AD / CRIT ITEMS ===
        R(items, 3078, "Trinity Force", ItemCategory.ADHealth, 3333,
            new ItemStats { Health = 300, AttackDamage = 35, AttackSpeedPercent = 30, AbilityHaste = 20 },
            new[] { 3057, 3044 }); // Spellblade

        R(items, 3046, "Phantom Dancer", ItemCategory.ADCrit, 2600,
            new ItemStats { AttackSpeedPercent = 35, CritChancePercent = 25, MoveSpeed = 7 },
            new[] { 3086 });

        R(items, 3085, "Runaan's Hurricane", ItemCategory.ADCrit, 2600,
            new ItemStats { AttackSpeedPercent = 45, CritChancePercent = 25, MoveSpeed = 7 },
            new[] { 3086, 1042 }); // Bolts passive

        R(items, 3094, "Rapid Firecannon", ItemCategory.ADCrit, 2500,
            new ItemStats { AttackSpeedPercent = 35, CritChancePercent = 25, MoveSpeed = 7 },
            new[] { 3086 }); // Energized

        R(items, 3095, "Stormrazor", ItemCategory.ADCrit, 2700,
            new ItemStats { AttackDamage = 40, AttackSpeedPercent = 15, CritChancePercent = 25 },
            new[] { 1038, 1042 }); // Energized

        R(items, 6671, "Galeforce", ItemCategory.ADCrit, 3200,
            new ItemStats { AttackDamage = 60, AttackSpeedPercent = 20, CritChancePercent = 25 },
            new[] { 1038, 3086 }); // Dash active

        R(items, 6675, "Navori Quickblades", ItemCategory.ADCrit, 3400,
            new ItemStats { AttackDamage = 60, CritChancePercent = 25, AbilityHaste = 20 },
            new[] { 1038, 1018 }); // CDR on crit

        R(items, 3179, "Umbral Glaive", ItemCategory.ADLethality, 2400,
            new ItemStats { AttackDamage = 50, Lethality = 10, AbilityHaste = 15 },
            new[] { 1036, 1036 }); // Ward detection

        R(items, 6694, "Serylda's Grudge", ItemCategory.ADHealth, 3200,
            new ItemStats { AttackDamage = 45, AbilityHaste = 20 },
            new[] { 3133 }); // +30% armor pen passive

        R(items, 6695, "Serpent's Fang", ItemCategory.ADLethality, 2600,
            new ItemStats { AttackDamage = 55, Lethality = 12 },
            new[] { 1036, 1036 }); // Shield reaver

        R(items, 6696, "Axiom Arc", ItemCategory.ADLethality, 3000,
            new ItemStats { AttackDamage = 55, Lethality = 10, AbilityHaste = 25 },
            new[] { 3133 }); // Ult CDR on kill

        R(items, 3161, "Spear of Shojin", ItemCategory.ADHealth, 3400,
            new ItemStats { Health = 300, AttackDamage = 55, AbilityHaste = 20 },
            new[] { 3133, 3067 });

        R(items, 6609, "Chempunk Chainsword", ItemCategory.ADHealth, 2600,
            new ItemStats { Health = 250, AttackDamage = 45, AbilityHaste = 15 },
            new[] { 3133 }); // Grievous wounds

        R(items, 6333, "Death's Dance", ItemCategory.ADHealth, 3300,
            new ItemStats { AttackDamage = 55, Armor = 45, AbilityHaste = 15 },
            new[] { 3133, 1029 }); // Damage delay

        R(items, 3181, "Hullbreaker", ItemCategory.ADHealth, 2800,
            new ItemStats { Health = 400, AttackDamage = 50 },
            new[] { 1037, 1028 }); // Split push

        R(items, 6035, "Silvermere Dawn", ItemCategory.ADHealth, 3000,
            new ItemStats { Health = 300, AttackDamage = 40, MagicResist = 35 },
            new[] { 1037, 1033 }); // QSS active

        R(items, 3026, "Guardian Angel", ItemCategory.ADHealth, 3000,
            new ItemStats { AttackDamage = 40, Armor = 40 },
            new[] { 1038, 1029 }); // Revive passive

        // === AP ITEMS ===
        R(items, 3115, "Nashor's Tooth", ItemCategory.AP, 3000,
            new ItemStats { AbilityPower = 100, AttackSpeedPercent = 50, AbilityHaste = 15 },
            new[] { 1043, 1052 }); // On-hit AP damage

        R(items, 3091, "Wit's End", ItemCategory.ADAttackSpeed, 2800,
            new ItemStats { AttackDamage = 30, AttackSpeedPercent = 40, MagicResist = 40, MoveSpeed = 5 },
            new[] { 1043, 1033 }); // On-hit magic damage

        R(items, 4628, "Horizon Focus", ItemCategory.AP, 2700,
            new ItemStats { AbilityPower = 85, Health = 150, AbilityHaste = 15 },
            new[] { 1026, 1028 }); // Hypershot

        R(items, 4629, "Cosmic Drive", ItemCategory.AP, 2900,
            new ItemStats { AbilityPower = 75, Health = 250, AbilityHaste = 25, MoveSpeed = 5 },
            new[] { 1026, 3067 }); // MS on ability

        R(items, 4633, "Riftmaker", ItemCategory.AP, 3100,
            new ItemStats { AbilityPower = 80, Health = 350, AbilityHaste = 15 },
            new[] { 1026, 1028 }); // Omnivamp + true damage

        R(items, 4636, "Night Harvester", ItemCategory.AP, 2800,
            new ItemStats { AbilityPower = 80, Health = 250, AbilityHaste = 25 },
            new[] { 1052, 1028 }); // Burst + MS

        R(items, 4637, "Demonic Embrace", ItemCategory.AP, 3000,
            new ItemStats { AbilityPower = 60, Health = 450 },
            new[] { 1026, 1028 }); // Burn passive

        R(items, 6653, "Liandry's Anguish", ItemCategory.AP, 3200,
            new ItemStats { AbilityPower = 80, Mana = 600, AbilityHaste = 20 },
            new[] { 1026, 3024 }); // Burn passive

        R(items, 6655, "Luden's Tempest", ItemCategory.AP, 3200,
            new ItemStats { AbilityPower = 80, Mana = 600, AbilityHaste = 20, MoveSpeed = 6 },
            new[] { 1058, 3024 }); // Echo burst

        R(items, 6656, "Everfrost", ItemCategory.AP, 2800,
            new ItemStats { AbilityPower = 70, Mana = 600, Health = 250, AbilityHaste = 15 },
            new[] { 1026, 3024 }); // Root active

        R(items, 6657, "Rod of Ages", ItemCategory.AP, 2800,
            new ItemStats { AbilityPower = 60, Health = 300, Mana = 400, AbilityHaste = 10 },
            new[] { 1026, 1028 }); // Stacking stats

        R(items, 3102, "Banshee's Veil", ItemCategory.AP, 2600,
            new ItemStats { AbilityPower = 80, MagicResist = 45, AbilityHaste = 10 },
            new[] { 1052, 1033 }); // Spell shield

        R(items, 4645, "Shadowflame", ItemCategory.AP, 3000,
            new ItemStats { AbilityPower = 100, Health = 200 },
            new[] { 1058, 1028 }); // Magic pen vs shields

        R(items, 3118, "Malignance", ItemCategory.AP, 2700,
            new ItemStats { AbilityPower = 80, Mana = 600, AbilityHaste = 25 },
            new[] { 1026, 3024 }); // Ult AH

        R(items, 3145, "Hextech Alternator", ItemCategory.Component, 1050,
            new ItemStats { AbilityPower = 40 }); // Burst damage

        R(items, 4646, "Stormsurge", ItemCategory.AP, 2900,
            new ItemStats { AbilityPower = 90, MoveSpeed = 5 },
            new[] { 3145, 3113 }); // Squall passive

        // === TANK ITEMS ===
        R(items, 6662, "Iceborn Gauntlet", ItemCategory.Tank, 2800,
            new ItemStats { Health = 300, Armor = 50, AbilityHaste = 20 },
            new[] { 3057, 3024 }); // Slow field

        R(items, 3110, "Frozen Heart", ItemCategory.Tank, 2500,
            new ItemStats { Armor = 80, Mana = 400, AbilityHaste = 20 },
            new[] { 3024, 1029 }); // AS slow aura

        R(items, 3119, "Winter's Approach", ItemCategory.Tank, 2600,
            new ItemStats { Health = 350, Mana = 500, AbilityHaste = 15 },
            new[] { 1028, 3024 }); // Evolves to Fimbulwinter

        R(items, 3748, "Titanic Hydra", ItemCategory.Tank, 3300,
            new ItemStats { Health = 500, AttackDamage = 40 },
            new[] { 3077, 1028 }); // Cleave based on HP

        R(items, 6665, "Jak'Sho", ItemCategory.Tank, 3200,
            new ItemStats { Health = 300, Armor = 30, MagicResist = 30, AbilityHaste = 20 },
            new[] { 3067, 1029, 1033 }); // Scaling resistances

        R(items, 3084, "Heartsteel", ItemCategory.Tank, 3200,
            new ItemStats { Health = 800, AbilityHaste = 20 },
            new[] { 1028, 3067 }); // HP stacking

        R(items, 6667, "Hollow Radiance", ItemCategory.Tank, 2800,
            new ItemStats { Health = 350, MagicResist = 60, AbilityHaste = 10 },
            new[] { 3067, 1033 }); // AoE magic damage

        R(items, 3050, "Zeke's Convergence", ItemCategory.TankSupport, 2400,
            new ItemStats { Health = 250, Armor = 25, MagicResist = 25, AbilityHaste = 20 },
            new[] { 3067, 1029 }); // Ally buff

        R(items, 3109, "Knight's Vow", ItemCategory.TankSupport, 2200,
            new ItemStats { Health = 200, AbilityHaste = 15 },
            new[] { 3067 }); // Redirect damage

        R(items, 2502, "Unending Despair", ItemCategory.Tank, 2800,
            new ItemStats { Health = 400, Armor = 45, AbilityHaste = 10 },
            new[] { 1031, 1028 }); // Drain aura

        R(items, 3002, "Trailblazer", ItemCategory.Tank, 2500,
            new ItemStats { Health = 250, Armor = 25, MagicResist = 25, MoveSpeed = 5 },
            new[] { 3066, 1029 }); // MS boost for team

        R(items, 6664, "Turbo Chemtank", ItemCategory.Tank, 2800,
            new ItemStats { Health = 350, Armor = 25, MagicResist = 25, AbilityHaste = 20 },
            new[] { 3067, 1029, 1033 }); // Supercharged active

        R(items, 3082, "Warden's Mail", ItemCategory.Component, 1000,
            new ItemStats { Armor = 40 }); // AS slow on hit

        R(items, 3211, "Spectre's Cowl", ItemCategory.Component, 1250,
            new ItemStats { Health = 250, MagicResist = 25 }); // Regen after dmg

        R(items, 2504, "Kaenic Rookern", ItemCategory.Tank, 2900,
            new ItemStats { Health = 350, MagicResist = 80 },
            new[] { 3211 }); // Magic shield

        // === SUPPORT ITEMS ===
        R(items, 3107, "Redemption", ItemCategory.APSupport, 2300,
            new ItemStats { Health = 200, ManaRegen = 5 },
            new[] { 3114, 1028 }); // AoE heal active

        R(items, 3222, "Mikael's Blessing", ItemCategory.APSupport, 2300,
            new ItemStats { MagicResist = 50, ManaRegen = 5 },
            new[] { 3114, 1033 }); // Cleanse active

        R(items, 3153, "Staff of Flowing Water", ItemCategory.APSupport, 2300,
            new ItemStats { AbilityPower = 50, ManaRegen = 5, AbilityHaste = 10 },
            new[] { 3114 }); // AP boost on heal

        R(items, 2501, "Echoes of Helia", ItemCategory.APSupport, 2300,
            new ItemStats { AbilityPower = 40, Health = 200, AbilityHaste = 15, ManaRegen = 5 },
            new[] { 3114, 1028 }); // Heal on damage

        R(items, 6617, "Moonstone Renewer", ItemCategory.APSupport, 2500,
            new ItemStats { AbilityPower = 40, Health = 200, AbilityHaste = 20, ManaRegen = 5 },
            new[] { 3114, 3067 }); // Chain heal

        R(items, 6620, "Dream Maker", ItemCategory.APSupport, 2500,
            new ItemStats { Health = 250, Armor = 30, MagicResist = 30, ManaRegen = 5 },
            new[] { 3114, 1028 }); // Bonus on-hit for allies

        // === JUNGLE ITEMS ===
        R(items, 1101, "Scorchclaw Pup", ItemCategory.Starter, 450,
            new ItemStats { AbilityHaste = 10 }); // Jungle starter

        R(items, 1102, "Gustwalker Hatchling", ItemCategory.Starter, 450,
            new ItemStats { AbilityHaste = 10 }); // Jungle starter

        R(items, 1103, "Mosstomper Seedling", ItemCategory.Starter, 450,
            new ItemStats { AbilityHaste = 10 }); // Jungle starter

        // === ELIXIRS ===
        R(items, 2138, "Elixir of Iron", ItemCategory.Consumable, 500,
            new ItemStats { Health = 300 }); // Tenacity + size

        R(items, 2139, "Elixir of Sorcery", ItemCategory.Consumable, 500,
            new ItemStats { AbilityPower = 50 }); // Bonus true dmg

        R(items, 2140, "Elixir of Wrath", ItemCategory.Consumable, 500,
            new ItemStats { AttackDamage = 30 }); // Lifesteal

        // === CONTROL WARDS ===
        R(items, 2055, "Control Ward", ItemCategory.Consumable, 75, new ItemStats());
        R(items, 3363, "Farsight Alteration", ItemCategory.Trinket, 0, new ItemStats());
    }

    private static void R(System.Collections.Generic.Dictionary<int, ItemData> items,
        int id, string name, ItemCategory cat, int cost, ItemStats stats, int[]? recipe = null)
    {
        items[id] = new ItemData
        {
            Id = id,
            Name = name,
            Category = cat,
            TotalCost = cost,
            Stats = stats,
            Recipe = recipe ?? Array.Empty<int>()
        };
    }
}
