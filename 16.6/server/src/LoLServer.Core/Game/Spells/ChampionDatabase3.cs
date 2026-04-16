using LoLServer.Core.Game.Combat;

namespace LoLServer.Core.Game.Spells;

/// <summary>
/// Extended champion database part 3: G-K champions.
/// Galio, Gangplank, Gnar, Gragas, Graves, Gwen, Hecarim, Heimerdinger,
/// Hwei, Illaoi, Ivern, Jarvan IV, Jayce, Kai'Sa (already), Kalista,
/// Karma, Karthus, Kassadin, Kayle, Kayn, Kennen, Kha'Zix, Kindred,
/// Kled, Kog'Maw, KSante
/// </summary>
public static class ChampionDatabase3
{
    public static void RegisterAll(System.Collections.Generic.Dictionary<string, ChampionSpellKit> registry)
    {
        registry["Galio"] = Kit(
            Q("Winds of War", DamageType.Magic, D(70,105,140,175,210), 0, 0.75f, CD(12,10.5f,9,7.5f,6), 825, 70),
            Q("Shield of Durand", DamageType.Magic, D(20,35,50,65,80), 0, 0.3f, CD(18,16.5f,15,13.5f,12), 0, 50),
            Q("Justice Punch", DamageType.Magic, D(90,130,170,210,250), 0, 0.9f, CD(12,11,10,9,8), 650, 50),
            Q("Hero's Entrance", DamageType.Magic, D(150,250,350), 0, 0.7f, CD(180,150,120), 5500, 100));

        registry["Gangplank"] = Kit(
            Q("Parrrley", DamageType.Physical, D(20,45,70,95,120), 1.0f, 0, CD(5,5,5,5,5), 625, 55),
            Q("Remove Scurvy", DamageType.Magic, D(0,0,0,0,0), 0, 0.4f, CD(22,20,18,16,14), 0, 80),
            Q("Powder Keg", DamageType.Physical, D(80,105,130,155,180), 1.0f, 0, CD(18,16,14,12,10), 1000, 0),
            Q("Cannon Barrage", DamageType.Magic, D(40,70,100), 0, 0.1f, CD(170,150,130), 99999, 100));

        registry["Gnar"] = Kit(
            Q("Boomerang Throw", DamageType.Physical, D(5,45,85,125,165), 1.15f, 0, CD(20,17.5f,15,12.5f,10), 1100, 0),
            Q("Hyper", DamageType.Magic, D(0,10,20,30,40), 0, 1.0f, CD(0), 0, 0),
            Q("Hop", DamageType.Physical, D(50,85,120,155,190), 0.6f, 0, CD(22,19.5f,17,14.5f,12), 475, 0),
            Q("GNAR!", DamageType.Physical, D(200,300,400), 0.5f, 0.5f, CD(90,60,30), 590, 0));

        registry["Gragas"] = Kit(
            Q("Barrel Roll", DamageType.Magic, D(80,120,160,200,240), 0, 0.7f, CD(11,10,9,8,7), 850, 60),
            Q("Drunken Rage", DamageType.Magic, D(20,50,80,110,140), 0, 0.5f, CD(5), 0, 30),
            Q("Body Slam", DamageType.Magic, D(80,130,180,230,280), 0, 0.6f, CD(14,13,12,11,10), 600, 50),
            Q("Explosive Cask", DamageType.Magic, D(200,300,400), 0, 0.8f, CD(120,100,80), 1000, 100));

        registry["Graves"] = Kit(
            Q("End of the Line", DamageType.Physical, D(45,60,75,90,105), 0.8f, 0, CD(13,11.5f,10,8.5f,7), 925, 60),
            Q("Smoke Screen", DamageType.Magic, D(60,110,160,210,260), 0, 0.6f, CD(26,24,22,20,18), 950, 70),
            Q("Quickdraw", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(16,14,12,10,8), 425, 40),
            Q("Collateral Damage", DamageType.Physical, D(250,400,550), 1.5f, 0, CD(120,90,60), 1000, 100));

        registry["Gwen"] = Kit(
            Q("Snip Snip!", DamageType.Magic, D(10,14,18,22,26), 0, 0.05f, CD(6.5f,5.75f,5,4.25f,3.5f), 450, 40),
            Q("Hallowed Mist", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(22,21,20,19,18), 0, 60),
            Q("Skip 'n Slash", DamageType.Magic, D(10,20,30,40,50), 0, 0.15f, CD(13,12,11,10,9), 450, 35),
            Q("Needlework", DamageType.Magic, D(30,55,80), 0, 0.08f, CD(120,100,80), 1250, 100));

        registry["Hecarim"] = Kit(
            Q("Rampage", DamageType.Physical, D(60,97,134,171,208), 0.85f, 0, CD(4), 350, 28),
            Q("Spirit of Dread", DamageType.Magic, D(20,30,40,50,60), 0, 0.2f, CD(18), 350, 50),
            Q("Devastating Charge", DamageType.Physical, D(30,50,70,90,110), 0.55f, 0, CD(20,19,18,17,16), 0, 0),
            Q("Onslaught of Shadows", DamageType.Magic, D(150,250,350), 0, 1.0f, CD(140,120,100), 1000, 100));

        registry["Heimerdinger"] = Kit(
            Q("H-28G Evolution Turret", DamageType.Magic, D(12,18,24,30,36), 0, 0.3f, CD(1), 450, 20),
            Q("Hextech Micro-Rockets", DamageType.Magic, D(60,90,120,150,180), 0, 0.45f, CD(11,10,9,8,7), 1325, 50),
            Q("CH-2 Electron Storm Grenade", DamageType.Magic, D(60,100,140,180,220), 0, 0.6f, CD(12,11,10,9,8), 970, 85),
            Q("UPGRADE!!!", DamageType.Magic, D(0,0,0), 0, 0, CD(100,85,70), 0, 100));

        registry["Hwei"] = Kit(
            Q("Subject: Disaster", DamageType.Magic, D(60,90,120,150,180), 0, 0.65f, CD(9,8,7,6,5), 950, 60),
            Q("Subject: Serenity", DamageType.Magic, D(0,0,0,0,0), 0, 0.3f, CD(14,13,12,11,10), 800, 70),
            Q("Subject: Torment", DamageType.Magic, D(50,75,100,125,150), 0, 0.45f, CD(12,11,10,9,8), 900, 55),
            Q("Spiraling Despair", DamageType.Magic, D(175,300,425), 0, 0.8f, CD(120,100,80), 950, 100));

        registry["Illaoi"] = Kit(
            Q("Tentacle Smash", DamageType.Physical, D(10,30,50,70,90), 1.2f, 0, CD(10,9,8,7,6), 825, 40),
            Q("Harsh Lesson", DamageType.Physical, D(0,0,0,0,0), 0.35f, 0, CD(6,5.5f,5,4.5f,4), 0, 30),
            Q("Test of Spirit", DamageType.Physical, D(25,50,75,100,125), 0.8f, 0, CD(16,15,14,13,12), 900, 35),
            Q("Leap of Faith", DamageType.Physical, D(150,250,350), 0.5f, 0, CD(120,95,70), 450, 100));

        registry["Ivern"] = Kit(
            Q("Rootcaller", DamageType.Magic, D(80,125,170,215,260), 0, 0.7f, CD(12,11,10,9,8), 1100, 60),
            Q("Brushmaker", DamageType.Magic, D(30,37,44,51,58), 0, 0.15f, CD(0.5f), 0, 30),
            Q("Triggerseed", DamageType.Magic, D(70,95,120,145,170), 0, 0.8f, CD(12,11,10,9,8), 750, 50),
            Q("Daisy!", DamageType.Magic, D(0,0,0), 0, 0, CD(140,130,120), 0, 100));

        registry["JarvanIV"] = Kit(
            Q("Dragon Strike", DamageType.Physical, D(80,120,160,200,240), 1.4f, 0, CD(10,9,8,7,6), 770, 45),
            Q("Golden Aegis", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(9), 0, 30),
            Q("Demacian Standard", DamageType.Magic, D(80,120,160,200,240), 0, 0.8f, CD(12,11.5f,11,10.5f,10), 860, 55),
            Q("Cataclysm", DamageType.Physical, D(200,325,450), 1.8f, 0, CD(120,105,90), 650, 100));

        registry["Jayce"] = Kit(
            Q("Shock Blast", DamageType.Physical, D(55,105,155,205,255), 1.2f, 0, CD(8), 1050, 55),
            Q("Lightning Field", DamageType.Magic, D(60,110,160,210,260), 0, 1.0f, CD(10), 285, 40),
            Q("Thundering Blow", DamageType.Magic, D(0,0,0,0,0), 0.75f, 0, CD(20,18,16,14,12), 240, 40),
            Q("Mercury Cannon", DamageType.Physical, D(0,0,0), 0, 0, CD(6), 0, 0));

        registry["Kalista"] = Kit(
            Q("Pierce", DamageType.Physical, D(20,85,150,215,280), 1.05f, 0, CD(8,7.5f,7,6.5f,6), 1150, 50),
            Q("Sentinel", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(30), 5500, 20),
            Q("Rend", DamageType.Physical, D(20,30,40,50,60), 0.7f, 0, CD(14,12.5f,11,9.5f,8), 1000, 30),
            Q("Fate's Call", DamageType.Magic, D(0,0,0), 0, 0, CD(120,100,80), 1100, 100));

        registry["Karma"] = Kit(
            Q("Inner Flame", DamageType.Magic, D(90,135,180,225,270), 0, 0.6f, CD(7,6.5f,6,5.5f,5), 950, 55),
            Q("Focused Resolve", DamageType.Magic, D(40,65,90,115,140), 0, 0.45f, CD(12), 675, 50),
            Q("Inspire", DamageType.Magic, D(0,0,0,0,0), 0, 0.3f, CD(10,9.5f,9,8.5f,8), 800, 50),
            Q("Mantra", DamageType.Magic, D(0,0,0), 0, 0, CD(40,38,36,34,32), 0, 0));

        registry["Karthus"] = Kit(
            Q("Lay Waste", DamageType.Magic, D(45,62,79,96,113), 0, 0.35f, CD(1), 875, 20),
            Q("Wall of Pain", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(15), 1000, 70),
            Q("Defile", DamageType.Magic, D(30,50,70,90,110), 0, 0.2f, CD(0.5f), 425, 30),
            Q("Requiem", DamageType.Magic, D(200,350,500), 0, 0.75f, CD(200,180,160), 99999, 100));

        registry["Kassadin"] = Kit(
            Q("Null Sphere", DamageType.Magic, D(65,95,125,155,185), 0, 0.7f, CD(11,10.5f,10,9.5f,9), 650, 70),
            Q("Nether Blade", DamageType.Magic, D(70,95,120,145,170), 0, 0.8f, CD(7), 200, 0),
            Q("Force Pulse", DamageType.Magic, D(80,105,130,155,180), 0, 0.85f, CD(5), 600, 0),
            Q("Riftwalk", DamageType.Magic, D(80,100,120), 0, 0.4f, CD(5,3.5f,2), 500, 40));

        registry["Kayle"] = Kit(
            Q("Radiant Blast", DamageType.Magic, D(60,100,140,180,220), 0.6f, 0.5f, CD(12,11,10,9,8), 900, 70),
            Q("Celestial Blessing", DamageType.Magic, D(55,80,105,130,155), 0, 0.25f, CD(15), 900, 70),
            Q("Starfire Spellblade", DamageType.Magic, D(20,25,30,35,40), 0, 0.25f, CD(0), 0, 0),
            Q("Divine Judgment", DamageType.Magic, D(200,350,500), 0, 0.8f, CD(160,120,80), 900, 100));

        registry["Kayn"] = Kit(
            Q("Reaping Slash", DamageType.Physical, D(75,95,115,135,155), 0.65f, 0, CD(7,6.5f,6,5.5f,5), 350, 0),
            Q("Blade's Reach", DamageType.Physical, D(90,135,180,225,270), 1.3f, 0, CD(13,12,11,10,9), 700, 60),
            Q("Shadow Step", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(21,19,17,15,13), 0, 0),
            Q("Umbral Trespass", DamageType.Physical, D(150,250,350), 1.75f, 0, CD(120,100,80), 550, 0));

        registry["Kennen"] = Kit(
            Q("Thundering Shuriken", DamageType.Magic, D(75,120,165,210,255), 0, 0.75f, CD(8,7,6,5,4), 950, 60),
            Q("Electrical Surge", DamageType.Magic, D(60,85,110,135,160), 0, 0.8f, CD(14,12,10,8,6), 750, 40),
            Q("Lightning Rush", DamageType.Magic, D(80,120,160,200,240), 0, 0.8f, CD(10,9,8,7,6), 0, 100),
            Q("Slicing Maelstrom", DamageType.Magic, D(40,75,110), 0, 0.2f, CD(120), 550, 0));

        registry["KhaZix"] = Kit(
            Q("Taste Their Fear", DamageType.Physical, D(60,85,110,135,160), 1.3f, 0, CD(4), 325, 20),
            Q("Void Spike", DamageType.Physical, D(85,115,145,175,205), 1.0f, 0, CD(9), 1000, 55),
            Q("Leap", DamageType.Physical, D(65,100,135,170,205), 0.2f, 0, CD(20,18,16,14,12), 700, 50),
            Q("Void Assault", DamageType.Physical, D(0,0,0), 0, 0, CD(100,85,70), 0, 0));

        registry["Kindred"] = Kit(
            Q("Dance of Arrows", DamageType.Physical, D(60,90,120,150,180), 0.75f, 0, CD(8), 340, 35),
            Q("Wolf's Frenzy", DamageType.Physical, D(25,30,35,40,45), 0.2f, 0, CD(18,17,16,15,14), 800, 40),
            Q("Mounting Dread", DamageType.Physical, D(80,100,120,140,160), 0.8f, 0, CD(14,13,12,11,10), 500, 50),
            Q("Lamb's Respite", DamageType.Magic, D(0,0,0), 0, 0, CD(180,150,120), 500, 0));

        registry["Kled"] = Kit(
            Q("Bear Trap on a Rope", DamageType.Physical, D(30,55,80,105,130), 0.65f, 0, CD(9,8.5f,8,7.5f,7), 800, 0),
            Q("Violent Tendencies", DamageType.Physical, D(20,30,40,50,60), 0.05f, 0, CD(14,12.5f,11,9.5f,8), 0, 0),
            Q("Jousting", DamageType.Physical, D(35,60,85,110,135), 0.65f, 0, CD(14,13,12,11,10), 550, 0),
            Q("Chaaaaarge!!!", DamageType.Physical, D(0,0,0), 0, 0, CD(160,130,100), 99999, 0));

        registry["KogMaw"] = Kit(
            Q("Caustic Spittle", DamageType.Magic, D(90,140,190,240,290), 0.7f, 0.5f, CD(8), 1175, 40),
            Q("Bio-Arcane Barrage", DamageType.Magic, D(0,0,0,0,0), 0, 0.01f, CD(17), 0, 40),
            Q("Void Ooze", DamageType.Magic, D(60,105,150,195,240), 0, 0.7f, CD(12), 1280, 60),
            Q("Living Artillery", DamageType.Magic, D(100,140,180), 0.65f, 0.25f, CD(2,1.5f,1), 1800, 40));

        registry["KSante"] = Kit(
            Q("Ntofo Strikes", DamageType.Physical, D(30,50,70,90,110), 0.4f, 0, CD(3.5f), 465, 15),
            Q("Path Maker", DamageType.Physical, D(50,75,100,125,150), 0.5f, 0, CD(22,20.5f,19,17.5f,16), 0, 0),
            Q("Footwork", DamageType.Physical, D(25,75,125,175,225), 0.4f, 0, CD(9), 350, 0),
            Q("All Out", DamageType.Physical, D(35,60,85), 0, 0, CD(120,100,80), 500, 0));
    }

    private static float[] D(params float[] vals) => vals;
    private static float[] CD(params float[] vals) => vals;
    private static float[] CD(float v) => new[] { v, v, v, v, v };
    private static SpellData Q(string name, DamageType dt, float[] dmg, float ad, float ap, float[] cd, float range, float mana)
        => new(name, dt, dmg, ad, ap, cd, range, mana);
    private static ChampionSpellKit Kit(SpellData q, SpellData w, SpellData e, SpellData r)
        => new() { Q = q, W = w, E = e, R = r };
}
