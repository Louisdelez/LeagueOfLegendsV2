using LoLServer.Core.Game.Combat;

namespace LoLServer.Core.Game.Spells;

/// <summary>
/// Extended champion database part 2: A-F champions.
/// Aatrox, Alistar, Amumu, Anivia, Annie, Aphelios, Ashe, AurelionSol,
/// Aurora, Azir, Bard, BelVeth, Brand, Braum, Briar, Cassiopeia,
/// Cho'Gath, Corki, Diana, DrMundo, Draven, Ekko, Elise, Evelynn,
/// Fiddlesticks, Fizz
/// </summary>
public static class ChampionDatabase2
{
    public static void RegisterAll(System.Collections.Generic.Dictionary<string, ChampionSpellKit> registry)
    {
        registry["Aatrox"] = Kit(
            Q("The Darkin Blade", DamageType.Physical, D(10,30,50,70,90), 0.65f, 0, CD(14,12,10,8,6), 650, 0),
            Q("Infernal Chains", DamageType.Physical, D(30,50,70,90,110), 0.4f, 0, CD(20,18,16,14,12), 825, 0),
            Q("Umbral Dash", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(9,8,7,6,5), 300, 0),
            Q("World Ender", DamageType.Physical, D(0,0,0), 0, 0, CD(120,100,80), 0, 0));

        registry["Alistar"] = Kit(
            Q("Pulverize", DamageType.Magic, D(60,105,150,195,240), 0, 0.5f, CD(15,14,13,12,11), 365, 55),
            Q("Headbutt", DamageType.Magic, D(55,110,165,220,275), 0, 0.7f, CD(14,13,12,11,10), 650, 65),
            Q("Trample", DamageType.Magic, D(80,110,140,170,200), 0, 0.4f, CD(12,11.5f,11,10.5f,10), 350, 50),
            Q("Unbreakable Will", DamageType.Magic, D(0,0,0), 0, 0, CD(120,100,80), 0, 100));

        registry["Amumu"] = Kit(
            Q("Bandage Toss", DamageType.Magic, D(70,95,120,145,170), 0, 0.85f, CD(10,9.5f,9,8.5f,8), 1100, 30),
            Q("Despair", DamageType.Magic, D(12,16,20,24,28), 0, 0.01f, CD(1), 300, 8),
            Q("Tantrum", DamageType.Magic, D(65,100,135,170,205), 0, 0.5f, CD(9,8,7,6,5), 350, 35),
            Q("Curse of the Sad Mummy", DamageType.Magic, D(200,300,400), 0, 0.8f, CD(130,115,100), 550, 100));

        registry["Anivia"] = Kit(
            Q("Flash Frost", DamageType.Magic, D(50,70,90,110,130), 0, 0.25f, CD(12,11,10,9,8), 1100, 80),
            Q("Crystallize", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(17), 1000, 70),
            Q("Frostbite", DamageType.Magic, D(50,80,110,140,170), 0, 0.5f, CD(4), 600, 50),
            Q("Glacial Storm", DamageType.Magic, D(30,45,60), 0, 0.125f, CD(4,3,2), 685, 60));

        registry["Annie"] = Kit(
            Q("Disintegrate", DamageType.Magic, D(80,115,150,185,220), 0, 0.8f, CD(4), 625, 60),
            Q("Incinerate", DamageType.Magic, D(70,115,160,205,250), 0, 0.85f, CD(8), 600, 70),
            Q("Molten Shield", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(14,13,12,11,10), 0, 40),
            Q("Summon: Tibbers", DamageType.Magic, D(150,275,400), 0, 0.75f, CD(120,100,80), 600, 100));

        registry["Aphelios"] = Kit(
            Q("Weapon Ability", DamageType.Physical, D(60,85,110,135,160), 0.5f, 0, CD(9,8.25f,7.5f,6.75f,6), 1300, 60),
            Q("Phase", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(0.8f), 0, 0),
            Q("Weapon Swap", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(0.8f), 0, 0),
            Q("Moonlight Vigil", DamageType.Physical, D(125,175,225), 0.2f, 1.0f, CD(120,110,100), 1300, 100));

        registry["Ashe"] = Kit(
            Q("Ranger's Focus", DamageType.Physical, D(0,0,0,0,0), 1.05f, 0, CD(0), 600, 50),
            Q("Volley", DamageType.Physical, D(20,35,50,65,80), 1.0f, 0, CD(18,14.5f,11,7.5f,4), 1200, 75),
            Q("Hawkshot", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(90,80,70,60,50), 99999, 0),
            Q("Enchanted Crystal Arrow", DamageType.Magic, D(200,400,600), 0, 1.0f, CD(100,80,60), 99999, 100));

        registry["AurelionSol"] = Kit(
            Q("Breath of Light", DamageType.Magic, D(15,25,35,45,55), 0, 0.3f, CD(3), 750, 45),
            Q("Astral Flight", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(22,20.5f,19,17.5f,16), 5000, 80),
            Q("Singularity", DamageType.Magic, D(20,35,50,65,80), 0, 0.2f, CD(12,11.5f,11,10.5f,10), 750, 70),
            Q("Falling Star", DamageType.Magic, D(150,250,350), 0, 0.65f, CD(120,100,80), 1250, 100));

        registry["Aurora"] = Kit(
            Q("Twisting Venom", DamageType.Magic, D(60,90,120,150,180), 0, 0.5f, CD(10,9.5f,9,8.5f,8), 850, 55),
            Q("Across the Veil", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(22,20,18,16,14), 500, 60),
            Q("The Weirding", DamageType.Magic, D(60,95,130,165,200), 0, 0.55f, CD(11,10,9,8,7), 750, 65),
            Q("Between Worlds", DamageType.Magic, D(150,250,350), 0, 0.7f, CD(130,110,90), 900, 100));

        registry["Azir"] = Kit(
            Q("Conquering Sands", DamageType.Magic, D(70,90,110,130,150), 0, 0.3f, CD(15,13,11,9,7), 740, 55),
            Q("Arise!", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(1.5f), 500, 40),
            Q("Shifting Sands", DamageType.Magic, D(60,90,120,150,180), 0, 0.4f, CD(19,18,17,16,15), 1100, 70),
            Q("Emperor's Divide", DamageType.Magic, D(175,325,475), 0, 0.6f, CD(120,105,90), 250, 100));

        registry["Bard"] = Kit(
            Q("Cosmic Binding", DamageType.Magic, D(80,120,160,200,240), 0, 0.65f, CD(11,10,9,8,7), 950, 60),
            Q("Caretaker's Shrine", DamageType.Magic, D(0,0,0,0,0), 0, 0.3f, CD(12), 800, 70),
            Q("Magical Journey", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(22,20,18,16,14), 900, 30),
            Q("Tempered Fate", DamageType.Magic, D(0,0,0), 0, 0, CD(110,95,80), 3400, 100));

        registry["BelVeth"] = Kit(
            Q("Void Surge", DamageType.Physical, D(10,25,40,55,70), 1.1f, 0, CD(16,15,14,13,12), 400, 0),
            Q("Above and Below", DamageType.Physical, D(70,110,150,190,230), 1.0f, 0, CD(12,11,10,9,8), 660, 0),
            Q("Royal Maelstrom", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(22,20,18,16,14), 0, 0),
            Q("Endless Banquet", DamageType.True, D(0,0,0), 0, 0, CD(120,100,80), 500, 0));

        registry["Brand"] = Kit(
            Q("Sear", DamageType.Magic, D(80,110,140,170,200), 0, 0.55f, CD(8,7.5f,7,6.5f,6), 1050, 50),
            Q("Pillar of Flame", DamageType.Magic, D(75,120,165,210,255), 0, 0.6f, CD(10,9.5f,9,8.5f,8), 900, 60),
            Q("Conflagration", DamageType.Magic, D(70,95,120,145,170), 0, 0.45f, CD(12,11,10,9,8), 625, 70),
            Q("Pyroclasm", DamageType.Magic, D(100,200,300), 0, 0.25f, CD(105,90,75), 750, 100));

        registry["Braum"] = Kit(
            Q("Winter's Bite", DamageType.Magic, D(60,105,150,195,240), 0, 0.025f, CD(10,9,8,7,6), 1000, 55),
            Q("Stand Behind Me", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(14,13,12,11,10), 650, 40),
            Q("Unbreakable", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(18,16,14,12,10), 0, 35),
            Q("Glacial Fissure", DamageType.Magic, D(150,250,350), 0, 0.6f, CD(140,120,100), 1250, 100));

        registry["Briar"] = Kit(
            Q("Head Rush", DamageType.Physical, D(60,90,120,150,180), 0.8f, 0, CD(13,12,11,10,9), 450, 0),
            Q("Blood Frenzy", DamageType.Physical, D(10,15,20,25,30), 0.6f, 0, CD(16,15,14,13,12), 0, 0),
            Q("Chilling Scream", DamageType.Physical, D(80,120,160,200,240), 1.0f, 0.8f, CD(16,15,14,13,12), 600, 0),
            Q("Certain Death", DamageType.Physical, D(150,300,450), 0.5f, 1.1f, CD(120,100,80), 10000, 0));

        registry["Cassiopeia"] = Kit(
            Q("Noxious Blast", DamageType.Magic, D(75,110,145,180,215), 0, 0.9f, CD(3.5f), 850, 50),
            Q("Miasma", DamageType.Magic, D(20,25,30,35,40), 0, 0.15f, CD(18,16.5f,15,13.5f,12), 800, 70),
            Q("Twin Fang", DamageType.Magic, D(52,70,88,106,124), 0, 0.1f, CD(0.75f), 700, 50),
            Q("Petrifying Gaze", DamageType.Magic, D(150,250,350), 0, 0.5f, CD(120,100,80), 825, 100));

        registry["ChoGath"] = Kit(
            Q("Rupture", DamageType.Magic, D(80,135,190,245,300), 0, 1.0f, CD(6), 950, 60),
            Q("Feral Scream", DamageType.Magic, D(75,125,175,225,275), 0, 0.7f, CD(13,12,11,10,9), 650, 70),
            Q("Vorpal Spikes", DamageType.Magic, D(22,34,46,58,70), 0, 0.3f, CD(0), 0, 0),
            Q("Feast", DamageType.True, D(300,475,650), 0.5f, 0.7f, CD(80), 175, 100));

        registry["Corki"] = Kit(
            Q("Phosphorus Bomb", DamageType.Magic, D(75,120,165,210,255), 0.5f, 0.7f, CD(8,7.5f,7,6.5f,6), 825, 60),
            Q("Valkyrie", DamageType.Magic, D(60,90,120,150,180), 0, 0.4f, CD(20,18,16,14,12), 600, 100),
            Q("Gatling Gun", DamageType.Physical, D(40,56,72,88,104), 0.2f, 0, CD(16), 600, 50),
            Q("Missile Barrage", DamageType.Magic, D(80,115,150), 0.2f, 0.12f, CD(2), 1300, 20));

        registry["Diana"] = Kit(
            Q("Crescent Strike", DamageType.Magic, D(60,95,130,165,200), 0, 0.7f, CD(8,7.5f,7,6.5f,6), 900, 50),
            Q("Pale Cascade", DamageType.Magic, D(18,30,42,54,66), 0, 0.15f, CD(15,13.5f,12,10.5f,9), 200, 40),
            Q("Lunar Rush", DamageType.Magic, D(40,60,80,100,120), 0, 0.4f, CD(22,20,18,16,14), 825, 40),
            Q("Moonfall", DamageType.Magic, D(200,300,400), 0, 0.6f, CD(100,90,80), 475, 100));

        registry["DrMundo"] = Kit(
            Q("Infected Bonesaw", DamageType.Magic, D(80,130,180,230,280), 0, 0, CD(4), 975, 50),
            Q("Heart Zapper", DamageType.Magic, D(20,35,50,65,80), 0, 0, CD(17,15.5f,14,12.5f,11), 325, 0),
            Q("Blunt Force Trauma", DamageType.Physical, D(5,15,25,35,45), 0.7f, 0, CD(9,8.5f,8,7.5f,7), 300, 0),
            Q("Maximum Dosage", DamageType.Magic, D(0,0,0), 0, 0, CD(110,100,90), 0, 0));

        registry["Draven"] = Kit(
            Q("Spinning Axe", DamageType.Physical, D(40,45,50,55,60), 0.75f, 0, CD(12,11,10,9,8), 0, 45),
            Q("Blood Rush", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(12), 0, 40),
            Q("Stand Aside", DamageType.Physical, D(75,110,145,180,215), 0.5f, 0, CD(18,17,16,15,14), 1050, 70),
            Q("Whirling Death", DamageType.Physical, D(175,275,375), 1.1f, 0, CD(100,90,80), 99999, 100));

        registry["Ekko"] = Kit(
            Q("Timewinder", DamageType.Magic, D(60,75,90,105,120), 0, 0.3f, CD(9,8.5f,8,7.5f,7), 1075, 50),
            Q("Parallel Convergence", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(22,20,18,16,14), 1600, 30),
            Q("Phase Dive", DamageType.Magic, D(50,75,100,125,150), 0, 0.4f, CD(9,8.5f,8,7.5f,7), 325, 40),
            Q("Chronobreak", DamageType.Magic, D(150,300,450), 0, 1.5f, CD(110,80,50), 0, 0));

        registry["Elise"] = Kit(
            Q("Neurotoxin", DamageType.Magic, D(40,75,110,145,180), 0, 0.04f, CD(6), 625, 80),
            Q("Volatile Spiderling", DamageType.Magic, D(60,105,150,195,240), 0, 0.95f, CD(12), 950, 60),
            Q("Cocoon", DamageType.Magic, D(40,75,110,145,180), 0, 0.04f, CD(12,11.5f,11,10.5f,10), 1075, 50),
            Q("Spider Form", DamageType.Magic, D(0,0,0), 0, 0, CD(4), 0, 0));

        registry["Evelynn"] = Kit(
            Q("Hate Spike", DamageType.Magic, D(25,30,35,40,45), 0, 0.25f, CD(4), 800, 12),
            Q("Allure", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(14,13,12,11,10), 1200, 60),
            Q("Whiplash", DamageType.Magic, D(55,70,85,100,115), 0, 0.3f, CD(8), 210, 40),
            Q("Last Caress", DamageType.Magic, D(125,250,375), 0, 0.75f, CD(120,100,80), 450, 100));

        registry["Fiddlesticks"] = Kit(
            Q("Terrify", DamageType.Magic, D(40,60,80,100,120), 0, 0.4f, CD(15,14,13,12,11), 575, 65),
            Q("Bountiful Harvest", DamageType.Magic, D(60,80,100,120,140), 0, 0.35f, CD(10,9,8,7,6), 650, 60),
            Q("Reap", DamageType.Magic, D(70,105,140,175,210), 0, 0.5f, CD(10,9.5f,9,8.5f,8), 750, 40),
            Q("Crowstorm", DamageType.Magic, D(325,525,725), 0, 1.125f, CD(140,110,80), 800, 100));

        registry["Fizz"] = Kit(
            Q("Urchin Strike", DamageType.Magic, D(10,25,40,55,70), 0, 0.55f, CD(8,7.5f,7,6.5f,6), 550, 40),
            Q("Seastone Trident", DamageType.Magic, D(50,70,90,110,130), 0, 0.5f, CD(7,6.5f,6,5.5f,5), 300, 30),
            Q("Playful/Trickster", DamageType.Magic, D(80,130,180,230,280), 0, 0.75f, CD(16,14,12,10,8), 400, 90),
            Q("Chum the Waters", DamageType.Magic, D(150,250,350), 0, 0.6f, CD(100,85,70), 1300, 100));
    }

    private static float[] D(params float[] vals) => vals;
    private static float[] CD(params float[] vals) => vals;
    private static float[] CD(float v) => new[] { v, v, v, v, v };
    private static SpellData Q(string name, DamageType dt, float[] dmg, float ad, float ap, float[] cd, float range, float mana)
        => new(name, dt, dmg, ad, ap, cd, range, mana);
    private static ChampionSpellKit Kit(SpellData q, SpellData w, SpellData e, SpellData r)
        => new() { Q = q, W = w, E = e, R = r };
}
