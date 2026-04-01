using LoLServer.Core.Game.Combat;

namespace LoLServer.Core.Game.Spells;

/// <summary>
/// Extended champion database part 4: L-R champions.
/// LeBlanc, Lillia, Lissandra, Lucian, Maokai, MasterYi, Milio,
/// Mordekaiser, Naafiri, Nasus, Neeko, Nidalee, Nilah, Nocturne,
/// Nunu, Olaf, Pantheon, Poppy, Pyke, Qiyana, Quinn, Rakan,
/// Rammus, RekSai, Rell, Renata, Rengar, Riven, Rumble, Ryze
/// </summary>
public static class ChampionDatabase4
{
    public static void RegisterAll(System.Collections.Generic.Dictionary<string, ChampionSpellKit> registry)
    {
        registry["LeBlanc"] = Kit(
            Q("Sigil of Malice", DamageType.Magic, D(65,90,115,140,165), 0, 0.4f, CD(6), 700, 50),
            Q("Distortion", DamageType.Magic, D(75,115,155,195,235), 0, 0.6f, CD(18,16,14,12,10), 600, 70),
            Q("Ethereal Chains", DamageType.Magic, D(50,70,90,110,130), 0, 0.3f, CD(14,13,12,11,10), 925, 70),
            Q("Mimic", DamageType.Magic, D(0,0,0), 0, 0, CD(60,45,30), 0, 0));

        registry["Lillia"] = Kit(
            Q("Blooming Blows", DamageType.Magic, D(35,45,55,65,75), 0, 0.4f, CD(6,5.5f,5,4.5f,4), 485, 45),
            Q("Watch Out! Eep!", DamageType.Magic, D(70,85,100,115,130), 0, 0.35f, CD(13,12,11,10,9), 350, 50),
            Q("Swirlseed", DamageType.Magic, D(70,95,120,145,170), 0, 0.45f, CD(12), 750, 70),
            Q("Lilting Lullaby", DamageType.Magic, D(100,150,200), 0, 0.3f, CD(130,110,90), 99999, 50));

        registry["Lissandra"] = Kit(
            Q("Ice Shard", DamageType.Magic, D(70,100,130,160,190), 0, 0.65f, CD(8,7,6,5,4), 725, 55),
            Q("Ring of Frost", DamageType.Magic, D(70,100,130,160,190), 0, 0.7f, CD(14,13,12,11,10), 450, 40),
            Q("Glacial Path", DamageType.Magic, D(70,105,140,175,210), 0, 0.6f, CD(24,21,18,15,12), 1050, 80),
            Q("Frozen Tomb", DamageType.Magic, D(150,250,350), 0, 0.6f, CD(120,100,80), 550, 100));

        registry["Lucian"] = Kit(
            Q("Piercing Light", DamageType.Physical, D(95,130,165,200,235), 0.6f, 0, CD(9,8,7,6,5), 500, 48),
            Q("Ardent Blaze", DamageType.Magic, D(75,110,145,180,215), 0, 0.9f, CD(13,12,11,10,9), 900, 70),
            Q("Relentless Pursuit", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(22,20,18,16,14), 425, 40),
            Q("The Culling", DamageType.Physical, D(20,40,60), 0.25f, 0.15f, CD(110,100,90), 1200, 100));

        registry["Maokai"] = Kit(
            Q("Bramble Smash", DamageType.Magic, D(65,110,155,200,245), 0, 0.4f, CD(8,7.25f,6.5f,5.75f,5), 600, 50),
            Q("Twisted Advance", DamageType.Magic, D(70,95,120,145,170), 0, 0.4f, CD(13,12,11,10,9), 525, 60),
            Q("Sapling Toss", DamageType.Magic, D(55,80,105,130,155), 0, 0.4f, CD(10), 1100, 60),
            Q("Nature's Grasp", DamageType.Magic, D(150,225,300), 0, 0.75f, CD(120,100,80), 3000, 100));

        registry["MasterYi"] = Kit(
            Q("Alpha Strike", DamageType.Physical, D(25,60,95,130,165), 0.6f, 0, CD(18,17,16,15,14), 600, 50),
            Q("Meditate", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(28), 0, 50),
            Q("Wuju Style", DamageType.True, D(18,26,34,42,50), 0.35f, 0, CD(18,17,16,15,14), 0, 0),
            Q("Highlander", DamageType.Physical, D(0,0,0), 0, 0, CD(85), 0, 0));

        registry["Milio"] = Kit(
            Q("Ultra Mega Fire Kick", DamageType.Magic, D(80,115,150,185,220), 0, 0.55f, CD(12,11,10,9,8), 1050, 50),
            Q("Cozy Campfire", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(17,16,15,14,13), 800, 90),
            Q("Warm Hugs", DamageType.Magic, D(60,80,100,120,140), 0, 0.25f, CD(0.5f), 650, 50),
            Q("Breath of Life", DamageType.Magic, D(0,0,0), 0, 0, CD(160,130,100), 700, 0));

        registry["Mordekaiser"] = Kit(
            Q("Obliterate", DamageType.Magic, D(75,95,115,135,155), 0, 0.6f, CD(9,7.75f,6.5f,5.25f,4), 625, 0),
            Q("Indestructible", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(14,13,12,11,10), 0, 0),
            Q("Death's Grasp", DamageType.Magic, D(75,95,115,135,155), 0, 0.6f, CD(18,16,14,12,10), 700, 0),
            Q("Realm of Death", DamageType.Magic, D(0,0,0), 0, 0, CD(120,100,80), 650, 0));

        registry["Naafiri"] = Kit(
            Q("Darkin Daggers", DamageType.Physical, D(30,65,100,135,170), 0.85f, 0, CD(10,9.5f,9,8.5f,8), 900, 55),
            Q("Hounds' Pursuit", DamageType.Physical, D(65,90,115,140,165), 0.8f, 0, CD(14,13,12,11,10), 700, 30),
            Q("Eviscerate", DamageType.Physical, D(65,100,135,170,205), 0.7f, 0, CD(12,11,10,9,8), 350, 0),
            Q("The Call of the Pack", DamageType.Physical, D(0,0,0), 0, 0, CD(120,100,80), 0, 0));

        registry["Nasus"] = Kit(
            Q("Siphoning Strike", DamageType.Physical, D(30,50,70,90,110), 1.0f, 0, CD(8,7,6,5,4), 300, 20),
            Q("Wither", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(15,14,13,12,11), 700, 80),
            Q("Spirit Fire", DamageType.Magic, D(55,95,135,175,215), 0, 0.6f, CD(12), 650, 70),
            Q("Fury of the Sands", DamageType.Magic, D(30,60,90), 0, 0.015f, CD(120), 0, 100));

        registry["Neeko"] = Kit(
            Q("Blooming Burst", DamageType.Magic, D(70,115,160,205,250), 0, 0.5f, CD(7), 800, 50),
            Q("Shapesplitter", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(20,19,18,17,16), 0, 0),
            Q("Tangle-Barbs", DamageType.Magic, D(80,115,150,185,220), 0, 0.6f, CD(12,11.5f,11,10.5f,10), 1000, 60),
            Q("Pop Blossom", DamageType.Magic, D(200,425,650), 0, 1.3f, CD(90), 600, 100));

        registry["Nidalee"] = Kit(
            Q("Javelin Toss", DamageType.Magic, D(70,85,100,115,130), 0, 0.4f, CD(6), 1500, 50),
            Q("Bushwhack", DamageType.Magic, D(40,80,120,160,200), 0, 0.2f, CD(13,12,11,10,9), 900, 40),
            Q("Primal Surge", DamageType.Magic, D(35,50,65,80,95), 0, 0.275f, CD(12), 600, 50),
            Q("Aspect of the Cougar", DamageType.Magic, D(0,0,0), 0, 0, CD(3), 0, 0));

        registry["Nilah"] = Kit(
            Q("Formless Blade", DamageType.Physical, D(5,10,15,20,25), 1.0f, 0, CD(4), 600, 30),
            Q("Jubilant Veil", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(26,22,18,14,10), 0, 0),
            Q("Slipstream", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(23,21,19,17,15), 550, 0),
            Q("Apotheosis", DamageType.Physical, D(60,120,180), 1.3f, 0, CD(120,100,80), 0, 0));

        registry["Nocturne"] = Kit(
            Q("Duskbringer", DamageType.Physical, D(65,110,155,200,245), 0.85f, 0, CD(10), 1200, 60),
            Q("Shroud of Darkness", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(20,18,16,14,12), 0, 50),
            Q("Unspeakable Horror", DamageType.Magic, D(80,120,160,200,240), 0, 1.0f, CD(15,14,13,12,11), 425, 60),
            Q("Paranoia", DamageType.Physical, D(150,275,400), 1.2f, 0, CD(150,125,100), 2500, 100));

        registry["Nunu"] = Kit(
            Q("Consume", DamageType.True, D(340,500,660,820,980), 0.5f, 0.9f, CD(12,11,10,9,8), 125, 60),
            Q("Biggest Snowball Ever!", DamageType.Magic, D(36,45,54,63,72), 0, 0.03f, CD(14), 0, 50),
            Q("Snowball Barrage", DamageType.Magic, D(16,24,32,40,48), 0, 0.06f, CD(14), 650, 50),
            Q("Absolute Zero", DamageType.Magic, D(625,950,1275), 0, 3.0f, CD(110,100,90), 650, 100));

        registry["Olaf"] = Kit(
            Q("Undertow", DamageType.Physical, D(60,110,160,210,260), 1.0f, 0, CD(7), 1000, 40),
            Q("Tough It Out", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(16,14.5f,13,11.5f,10), 0, 0),
            Q("Reckless Swing", DamageType.True, D(70,115,160,205,250), 0.5f, 0, CD(11,10,9,8,7), 325, 0),
            Q("Ragnarok", DamageType.Physical, D(0,0,0), 0, 0, CD(100,90,80), 0, 0));

        registry["Pantheon"] = Kit(
            Q("Comet Spear", DamageType.Physical, D(70,100,130,160,190), 1.15f, 0, CD(13,11.75f,10.5f,9.25f,8), 1200, 30),
            Q("Shield Vault", DamageType.Physical, D(60,80,100,120,140), 1.0f, 0, CD(13,12,11,10,9), 600, 55),
            Q("Aegis Assault", DamageType.Physical, D(55,105,155,205,255), 1.5f, 0, CD(22,20.5f,19,17.5f,16), 400, 80),
            Q("Grand Starfall", DamageType.Magic, D(200,350,500), 0, 0.7f, CD(180,165,150), 5500, 100));

        registry["Poppy"] = Kit(
            Q("Hammer Shock", DamageType.Physical, D(40,60,80,100,120), 0.9f, 0, CD(8,7,6,5,4), 430, 35),
            Q("Steadfast Presence", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(24,22,20,18,16), 0, 50),
            Q("Heroic Charge", DamageType.Physical, D(60,80,100,120,140), 0.5f, 0, CD(14,13,12,11,10), 475, 70),
            Q("Keeper's Verdict", DamageType.Physical, D(200,300,400), 0.9f, 0, CD(140,120,100), 1200, 100));

        registry["Pyke"] = Kit(
            Q("Bone Skewer", DamageType.Physical, D(75,125,175,225,275), 0.6f, 0, CD(12,11,10,9,8), 1100, 55),
            Q("Ghostwater Dive", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(12,11.5f,11,10.5f,10), 0, 50),
            Q("Phantom Undertow", DamageType.Physical, D(105,135,165,195,225), 1.0f, 0, CD(15,14,13,12,11), 550, 40),
            Q("Death from Below", DamageType.True, D(250,290,330,370,400,430,450,470,490,500,510,540,550), 0.8f, 0, CD(120,100,80), 750, 100));

        registry["Qiyana"] = Kit(
            Q("Elemental Wrath", DamageType.Physical, D(60,85,110,135,160), 0.75f, 0, CD(7), 525, 35),
            Q("Terrashape", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(7), 0, 25),
            Q("Audacity", DamageType.Physical, D(60,90,120,150,180), 0.5f, 0, CD(12,11,10,9,8), 650, 40),
            Q("Supreme Display of Talent", DamageType.Physical, D(100,200,300), 1.7f, 0, CD(120), 950, 100));

        registry["Quinn"] = Kit(
            Q("Blinding Assault", DamageType.Physical, D(20,45,70,95,120), 0.8f, 0.5f, CD(11,10.5f,10,9.5f,9), 1025, 50),
            Q("Heightened Senses", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(0), 0, 0),
            Q("Vault", DamageType.Physical, D(40,70,100,130,160), 0.2f, 0, CD(12,11,10,9,8), 675, 50),
            Q("Behind Enemy Lines", DamageType.Physical, D(0,0,0), 0, 0, CD(3), 0, 0));

        registry["Rakan"] = Kit(
            Q("Gleaming Quill", DamageType.Magic, D(70,115,160,205,250), 0, 0.55f, CD(12,11,10,9,8), 900, 60),
            Q("Grand Entrance", DamageType.Magic, D(70,125,180,235,290), 0, 0.7f, CD(18,16.5f,15,13.5f,12), 600, 50),
            Q("Battle Dance", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(20,18,16,14,12), 700, 60),
            Q("The Quickness", DamageType.Magic, D(100,200,300), 0, 0.5f, CD(130,110,90), 0, 100));

        registry["Rammus"] = Kit(
            Q("Powerball", DamageType.Magic, D(100,130,160,190,220), 0, 1.0f, CD(16,13.5f,11,8.5f,6), 0, 60),
            Q("Defensive Ball Curl", DamageType.Magic, D(10,15,20,25,30), 0, 0, CD(7), 0, 40),
            Q("Frenzying Taunt", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(12,11.5f,11,10.5f,10), 325, 50),
            Q("Soaring Slam", DamageType.Magic, D(100,175,250), 0.6f, 1.0f, CD(130,110,90), 600, 100));

        registry["RekSai"] = Kit(
            Q("Queen's Wrath", DamageType.Physical, D(21,27,33,39,45), 0.5f, 0, CD(12,11.5f,11,10.5f,10), 300, 0),
            Q("Burrow", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(1), 0, 0),
            Q("Furious Bite", DamageType.True, D(55,65,75,85,95), 0.7f, 0, CD(12), 250, 0),
            Q("Void Rush", DamageType.Physical, D(100,250,400), 1.75f, 0.2f, CD(100,80,60), 99999, 0));

        registry["Rell"] = Kit(
            Q("Shattering Strike", DamageType.Magic, D(60,90,120,150,180), 0, 0.5f, CD(11,10.5f,10,9.5f,9), 685, 25),
            Q("Ferromancy", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(13), 0, 0),
            Q("Full Tilt", DamageType.Magic, D(25,35,45,55,65), 0, 0.3f, CD(3), 0, 0),
            Q("Magnet Storm", DamageType.Magic, D(120,200,280), 0, 0.6f, CD(120,100,80), 400, 100));

        registry["Renata"] = Kit(
            Q("Handshake", DamageType.Magic, D(80,125,170,215,260), 0, 0.8f, CD(12,11,10,9,8), 900, 60),
            Q("Bailout", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(28,27,26,25,24), 800, 80),
            Q("Loyalty Program", DamageType.Magic, D(65,95,125,155,185), 0, 0.55f, CD(14,13,12,11,10), 950, 80),
            Q("Hostile Takeover", DamageType.Magic, D(0,0,0), 0, 0, CD(150,130,110), 99999, 100));

        registry["Rengar"] = Kit(
            Q("Savagery", DamageType.Physical, D(30,60,90,120,150), 1.0f, 0, CD(6,5.5f,5,4.5f,4), 300, 0),
            Q("Battle Roar", DamageType.Magic, D(50,80,110,140,170), 0, 0.8f, CD(16,14.5f,13,11.5f,10), 450, 0),
            Q("Bola Strike", DamageType.Physical, D(55,100,145,190,235), 0.8f, 0, CD(10), 1000, 0),
            Q("Thrill of the Hunt", DamageType.Physical, D(0,0,0), 0, 0, CD(110,90,70), 0, 0));

        registry["Riven"] = Kit(
            Q("Broken Wings", DamageType.Physical, D(15,35,55,75,95), 0.5f, 0, CD(13), 275, 0),
            Q("Ki Burst", DamageType.Physical, D(55,85,115,145,175), 1.0f, 0, CD(11,10,9,8,7), 250, 0),
            Q("Valor", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(10,9,8,7,6), 325, 0),
            Q("Blade of the Exile", DamageType.Physical, D(100,150,200), 0.6f, 0, CD(120,90,60), 900, 0));

        registry["Rumble"] = Kit(
            Q("Flamespitter", DamageType.Magic, D(135,180,225,270,315), 0, 1.1f, CD(6,5.5f,5,4.5f,4), 600, 0),
            Q("Scrap Shield", DamageType.Magic, D(0,0,0,0,0), 0, 0.4f, CD(6), 0, 0),
            Q("Electro Harpoon", DamageType.Magic, D(60,85,110,135,160), 0, 0.4f, CD(7,6.5f,6,5.5f,5), 850, 0),
            Q("The Equalizer", DamageType.Magic, D(130,185,240), 0, 0.3f, CD(110,100,90), 1700, 0));

        registry["Ryze"] = Kit(
            Q("Overload", DamageType.Magic, D(70,90,110,130,150), 0, 0.45f, CD(6,5.5f,5,4.5f,4), 1000, 40),
            Q("Rune Prison", DamageType.Magic, D(80,100,120,140,160), 0, 0.6f, CD(13,12,11,10,9), 615, 40),
            Q("Spell Flux", DamageType.Magic, D(60,80,100,120,140), 0, 0.4f, CD(3.25f,3,2.75f,2.5f,2.25f), 615, 40),
            Q("Realm Warp", DamageType.Magic, D(0,0,0), 0, 0, CD(210,180,150), 3000, 100));
    }

    private static float[] D(params float[] vals) => vals;
    private static float[] CD(params float[] vals) => vals;
    private static float[] CD(float v) => new[] { v, v, v, v, v };
    private static SpellData Q(string name, DamageType dt, float[] dmg, float ad, float ap, float[] cd, float range, float mana)
        => new(name, dt, dmg, ad, ap, cd, range, mana);
    private static ChampionSpellKit Kit(SpellData q, SpellData w, SpellData e, SpellData r)
        => new() { Q = q, W = w, E = e, R = r };
}
