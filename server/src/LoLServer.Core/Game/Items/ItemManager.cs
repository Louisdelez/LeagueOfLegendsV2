using System;
using System.Collections.Generic;
using System.Linq;
using LoLServer.Core.Game.Entities;

namespace LoLServer.Core.Game.Items;

/// <summary>
/// Manages the item shop, item data, recipes, and item effects.
/// Contains real LoL item data for the most important items.
/// </summary>
public static class ItemManager
{
    private static readonly Dictionary<int, ItemData> Items = new();

    static ItemManager()
    {
        RegisterAllItems();
    }

    public static ItemData? GetItem(int id) => Items.TryGetValue(id, out var item) ? item : null;
    public static IEnumerable<ItemData> GetAllItems() => Items.Values;

    public static IEnumerable<ItemData> GetItemsForCategory(ItemCategory category)
        => Items.Values.Where(i => i.Category == category);

    /// <summary>
    /// Attempt to buy an item for a champion. Handles gold check, recipe completion, inventory space.
    /// </summary>
    public static BuyResult TryBuyItem(Champion champion, int itemId)
    {
        var item = GetItem(itemId);
        if (item == null) return new BuyResult(false, "Item not found");

        // Check if we already have 6 items (full inventory)
        int emptySlot = -1;
        int componentSlot = -1;

        for (int i = 0; i < 6; i++)
        {
            if (champion.Items[i] == 0 && emptySlot == -1)
                emptySlot = i;
            // Check if we have a component to upgrade
            if (item.Recipe.Contains(champion.Items[i]) && componentSlot == -1)
                componentSlot = i;
        }

        // Calculate actual cost (subtract owned components)
        float actualCost = CalculateActualCost(champion, item);

        if (champion.Gold < actualCost)
            return new BuyResult(false, $"Not enough gold ({champion.Gold:F0}/{actualCost:F0})");

        // Find slot: upgrade component or use empty slot
        int targetSlot;
        if (componentSlot >= 0)
        {
            // Remove component, place completed item
            targetSlot = componentSlot;
        }
        else if (emptySlot >= 0)
        {
            targetSlot = emptySlot;
        }
        else
        {
            return new BuyResult(false, "Inventory full");
        }

        // Remove all owned components from inventory
        foreach (var compId in item.Recipe)
        {
            for (int i = 0; i < 6; i++)
            {
                if (champion.Items[i] == compId)
                {
                    champion.Items[i] = 0;
                    break;
                }
            }
        }

        // Place item and deduct gold
        champion.Items[targetSlot] = itemId;
        champion.Gold -= actualCost;

        // Apply stats
        ApplyItemStats(champion, item);

        return new BuyResult(true, $"Bought {item.Name} for {actualCost:F0}g");
    }

    public static void SellItem(Champion champion, int slot)
    {
        if (slot < 0 || slot >= 6 || champion.Items[slot] == 0) return;

        var item = GetItem(champion.Items[slot]);
        if (item == null) return;

        // Refund 70% of total cost
        champion.Gold += item.TotalCost * 0.7f;

        // Remove stats
        RemoveItemStats(champion, item);

        champion.Items[slot] = 0;
    }

    private static float CalculateActualCost(Champion champion, ItemData item)
    {
        float cost = item.TotalCost;

        // Subtract value of owned components
        foreach (var compId in item.Recipe)
        {
            for (int i = 0; i < 6; i++)
            {
                if (champion.Items[i] == compId)
                {
                    var comp = GetItem(compId);
                    if (comp != null) cost -= comp.TotalCost;
                    break;
                }
            }
        }

        return MathF.Max(0, cost);
    }

    private static void ApplyItemStats(Champion champion, ItemData item)
    {
        champion.MaxHealth += item.Stats.Health;
        champion.Health += item.Stats.Health;
        champion.MaxMana += item.Stats.Mana;
        champion.Mana += item.Stats.Mana;
        champion.AttackDamage += item.Stats.AttackDamage;
        champion.Armor += item.Stats.Armor;
        champion.MagicResist += item.Stats.MagicResist;
        champion.AttackSpeed *= (1 + item.Stats.AttackSpeedPercent / 100f);
        champion.MoveSpeed += item.Stats.MoveSpeed;
        champion.HealthRegen += item.Stats.HealthRegen;
        champion.ManaRegen += item.Stats.ManaRegen;
    }

    private static void RemoveItemStats(Champion champion, ItemData item)
    {
        champion.MaxHealth -= item.Stats.Health;
        champion.Health = MathF.Min(champion.Health, champion.MaxHealth);
        champion.MaxMana -= item.Stats.Mana;
        champion.Mana = MathF.Min(champion.Mana, champion.MaxMana);
        champion.AttackDamage -= item.Stats.AttackDamage;
        champion.Armor -= item.Stats.Armor;
        champion.MagicResist -= item.Stats.MagicResist;
        if (item.Stats.AttackSpeedPercent != 0)
            champion.AttackSpeed /= (1 + item.Stats.AttackSpeedPercent / 100f);
        champion.MoveSpeed -= item.Stats.MoveSpeed;
        champion.HealthRegen -= item.Stats.HealthRegen;
        champion.ManaRegen -= item.Stats.ManaRegen;
    }

    // ============== ITEM DATABASE ==============

    private static void RegisterAllItems()
    {
        // === STARTER ITEMS ===
        Register(1055, "Doran's Blade", ItemCategory.Starter, 450, new ItemStats { Health = 80, AttackDamage = 8 });
        Register(1056, "Doran's Ring", ItemCategory.Starter, 400, new ItemStats { Health = 70, Mana = 50, AbilityPower = 15 });
        Register(1054, "Doran's Shield", ItemCategory.Starter, 450, new ItemStats { Health = 80, HealthRegen = 6 });
        Register(1082, "Dark Seal", ItemCategory.Starter, 350, new ItemStats { Mana = 40, AbilityPower = 15 });
        Register(2003, "Health Potion", ItemCategory.Consumable, 50, new ItemStats());
        Register(2031, "Refillable Potion", ItemCategory.Consumable, 150, new ItemStats());
        Register(3340, "Stealth Ward", ItemCategory.Trinket, 0, new ItemStats());
        Register(3364, "Oracle Lens", ItemCategory.Trinket, 0, new ItemStats());

        // === BASIC COMPONENTS ===
        Register(1001, "Boots", ItemCategory.Boots, 300, new ItemStats { MoveSpeed = 25 });
        Register(1036, "Long Sword", ItemCategory.Component, 350, new ItemStats { AttackDamage = 10 });
        Register(1052, "Amplifying Tome", ItemCategory.Component, 435, new ItemStats { AbilityPower = 20 });
        Register(1058, "Needlessly Large Rod", ItemCategory.Component, 1250, new ItemStats { AbilityPower = 60 });
        Register(1026, "Blasting Wand", ItemCategory.Component, 850, new ItemStats { AbilityPower = 40 });
        Register(1028, "Ruby Crystal", ItemCategory.Component, 400, new ItemStats { Health = 150 });
        Register(1029, "Cloth Armor", ItemCategory.Component, 300, new ItemStats { Armor = 15 });
        Register(1033, "Null-Magic Mantle", ItemCategory.Component, 450, new ItemStats { MagicResist = 25 });
        Register(1042, "Dagger", ItemCategory.Component, 300, new ItemStats { AttackSpeedPercent = 12 });
        Register(1043, "Recurve Bow", ItemCategory.Component, 1000, new ItemStats { AttackSpeedPercent = 25 });
        Register(1037, "Pickaxe", ItemCategory.Component, 875, new ItemStats { AttackDamage = 25 });
        Register(1038, "B.F. Sword", ItemCategory.Component, 1300, new ItemStats { AttackDamage = 40 });
        Register(1018, "Cloak of Agility", ItemCategory.Component, 600, new ItemStats { CritChancePercent = 15 });
        Register(3024, "Glacial Buckler", ItemCategory.Component, 900, new ItemStats { Armor = 20, Mana = 250 });
        Register(3044, "Phage", ItemCategory.Component, 1100, new ItemStats { Health = 200, AttackDamage = 15 });
        Register(3067, "Kindlegem", ItemCategory.Component, 800, new ItemStats { Health = 200 }); // +10% CDR
        Register(3076, "Bramble Vest", ItemCategory.Component, 800, new ItemStats { Armor = 30 });

        // === BOOTS (COMPLETED) ===
        Register(3006, "Berserker's Greaves", ItemCategory.Boots, 1100, new ItemStats { MoveSpeed = 45, AttackSpeedPercent = 35 }, new[] { 1001 });
        Register(3009, "Boots of Swiftness", ItemCategory.Boots, 900, new ItemStats { MoveSpeed = 60 }, new[] { 1001 });
        Register(3020, "Sorcerer's Shoes", ItemCategory.Boots, 1100, new ItemStats { MoveSpeed = 45 }, new[] { 1001 }); // +18 magic pen
        Register(3047, "Plated Steelcaps", ItemCategory.Boots, 1100, new ItemStats { MoveSpeed = 45, Armor = 20 }, new[] { 1001, 1029 });
        Register(3111, "Mercury's Treads", ItemCategory.Boots, 1100, new ItemStats { MoveSpeed = 45, MagicResist = 25 }, new[] { 1001, 1033 });
        Register(3158, "Ionian Boots of Lucidity", ItemCategory.Boots, 950, new ItemStats { MoveSpeed = 45 }, new[] { 1001 }); // +20 AH

        // === AD ITEMS (COMPLETED) ===
        Register(3031, "Infinity Edge", ItemCategory.ADCrit, 3400, new ItemStats { AttackDamage = 70, CritChancePercent = 25 }, new[] { 1038, 1018, 1036 });
        Register(3072, "Bloodthirster", ItemCategory.ADCrit, 3400, new ItemStats { AttackDamage = 55 }, new[] { 1038, 1037 }); // +20% lifesteal
        Register(3153, "Blade of the Ruined King", ItemCategory.ADAttackSpeed, 3200, new ItemStats { AttackDamage = 40, AttackSpeedPercent = 25 }, new[] { 1043, 1036 }); // +12% lifesteal + %hp dmg
        Register(3004, "Manamune", ItemCategory.ADMana, 2900, new ItemStats { AttackDamage = 35, Mana = 500 }, new[] { 1037 }); // +15 AH
        Register(3071, "Black Cleaver", ItemCategory.ADHealth, 3000, new ItemStats { Health = 350, AttackDamage = 40 }, new[] { 3044, 3067 }); // +25 AH, armor shred
        Register(3074, "Ravenous Hydra", ItemCategory.ADLifesteal, 3300, new ItemStats { AttackDamage = 65 }, new[] { 1038, 1036 }); // +20 AH, omnivamp
        Register(3142, "Youmuu's Ghostblade", ItemCategory.ADLethality, 2800, new ItemStats { AttackDamage = 55 }, new[] { 1036, 1036 }); // +18 lethality, active MS
        Register(3156, "Maw of Malmortius", ItemCategory.ADHealth, 2800, new ItemStats { AttackDamage = 55, MagicResist = 40 }, new[] { 1037, 1033 }); // magic shield
        Register(6672, "Kraken Slayer", ItemCategory.ADCrit, 3100, new ItemStats { AttackDamage = 45, AttackSpeedPercent = 25, CritChancePercent = 25 }, new[] { 1043, 1018 });
        Register(6673, "Immortal Shieldbow", ItemCategory.ADCrit, 3000, new ItemStats { AttackDamage = 50, CritChancePercent = 25 }, new[] { 1038, 1018 }); // lifeline shield
        Register(6676, "The Collector", ItemCategory.ADLethality, 3000, new ItemStats { AttackDamage = 55, CritChancePercent = 25 }, new[] { 1038, 1018 }); // execute

        // === AP ITEMS (COMPLETED) ===
        Register(3089, "Rabadon's Deathcap", ItemCategory.AP, 3600, new ItemStats { AbilityPower = 120 }, new[] { 1058, 1026 }); // +35% AP
        Register(3135, "Void Staff", ItemCategory.AP, 2800, new ItemStats { AbilityPower = 65 }, new[] { 1026 }); // +40% magic pen
        Register(3157, "Zhonya's Hourglass", ItemCategory.AP, 2600, new ItemStats { AbilityPower = 80, Armor = 45 }, new[] { 1052, 1029 }); // stasis active
        Register(3165, "Morellonomicon", ItemCategory.AP, 2500, new ItemStats { AbilityPower = 80, Health = 300 }, new[] { 1052, 1028 }); // grievous wounds
        Register(3003, "Archangel's Staff", ItemCategory.APMana, 3000, new ItemStats { AbilityPower = 60, Mana = 600 }, new[] { 1026 }); // +20 AH, evolves
        Register(3100, "Lich Bane", ItemCategory.AP, 2800, new ItemStats { AbilityPower = 75, MoveSpeed = 8 }, new[] { 1052 }); // spellblade
        Register(3116, "Rylai's Crystal Scepter", ItemCategory.AP, 2600, new ItemStats { AbilityPower = 75, Health = 350 }, new[] { 1026, 1028 }); // slow
        Register(3152, "Hextech Rocketbelt", ItemCategory.AP, 2600, new ItemStats { AbilityPower = 60, Health = 250 }, new[] { 1052, 1028 }); // dash active
        Register(4005, "Imperial Mandate", ItemCategory.APSupport, 2300, new ItemStats { AbilityPower = 40, Health = 200 }, new[] { 1052, 1028 }); // mark

        // === TANK ITEMS ===
        Register(3068, "Sunfire Aegis", ItemCategory.Tank, 2700, new ItemStats { Health = 350, Armor = 35, MagicResist = 35 }, new[] { 3067, 1029 }); // immolate
        Register(3075, "Thornmail", ItemCategory.Tank, 2700, new ItemStats { Health = 350, Armor = 70 }, new[] { 3076, 1028 }); // reflect + grievous
        Register(3083, "Warmog's Armor", ItemCategory.Tank, 3000, new ItemStats { Health = 800, HealthRegen = 10 }, new[] { 1028, 1028 }); // regen passive
        Register(3143, "Randuin's Omen", ItemCategory.Tank, 2700, new ItemStats { Health = 250, Armor = 80 }, new[] { 1029 }); // AS slow active
        Register(3065, "Spirit Visage", ItemCategory.Tank, 2900, new ItemStats { Health = 450, MagicResist = 60, HealthRegen = 10 }, new[] { 3067, 1033 }); // +25% healing
        Register(3190, "Locket of the Iron Solari", ItemCategory.TankSupport, 2300, new ItemStats { Health = 200, Armor = 30, MagicResist = 30 }, new[] { 3067, 1029 }); // shield active
        Register(3742, "Dead Man's Plate", ItemCategory.Tank, 2900, new ItemStats { Health = 300, Armor = 45 }, new[] { 3044, 1029 }); // momentum

        // === SUPPORT ITEMS ===
        Register(3860, "Spellthief's Edge", ItemCategory.Support, 400, new ItemStats { AbilityPower = 8, HealthRegen = 2, ManaRegen = 2 });
        Register(3862, "Spectral Sickle", ItemCategory.Support, 400, new ItemStats { AttackDamage = 5, HealthRegen = 2 });
        Register(3858, "Relic Shield", ItemCategory.Support, 400, new ItemStats { Health = 30, HealthRegen = 2 });
        Register(3504, "Ardent Censer", ItemCategory.APSupport, 2300, new ItemStats { AbilityPower = 60, ManaRegen = 5 }, new[] { 1052 }); // heal buff
        Register(3011, "Chemtech Putrifier", ItemCategory.APSupport, 2300, new ItemStats { AbilityPower = 55, ManaRegen = 5 }, new[] { 1052 }); // grievous on heal
        Register(2065, "Shurelya's Battlesong", ItemCategory.APSupport, 2300, new ItemStats { AbilityPower = 40, Health = 200 }, new[] { 1052, 1028 }); // MS active
    }

    private static void Register(int id, string name, ItemCategory cat, int cost, ItemStats stats, int[]? recipe = null)
    {
        Items[id] = new ItemData
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

public class ItemData
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public ItemCategory Category { get; set; }
    public float TotalCost { get; set; }
    public ItemStats Stats { get; set; } = new();
    public int[] Recipe { get; set; } = Array.Empty<int>();
    public string? ActiveAbility { get; set; }
    public string? PassiveEffect { get; set; }
}

public class ItemStats
{
    public float Health { get; set; }
    public float Mana { get; set; }
    public float AttackDamage { get; set; }
    public float AbilityPower { get; set; }
    public float Armor { get; set; }
    public float MagicResist { get; set; }
    public float AttackSpeedPercent { get; set; }
    public float CritChancePercent { get; set; }
    public float MoveSpeed { get; set; }
    public float HealthRegen { get; set; }
    public float ManaRegen { get; set; }
    public float Lethality { get; set; }
    public float AbilityHaste { get; set; }
}

public enum ItemCategory
{
    Starter, Consumable, Trinket, Component, Boots,
    ADCrit, ADAttackSpeed, ADLethality, ADLifesteal, ADHealth, ADMana,
    AP, APMana, APSupport,
    Tank, TankSupport,
    Support
}

public record BuyResult(bool Success, string Message);
