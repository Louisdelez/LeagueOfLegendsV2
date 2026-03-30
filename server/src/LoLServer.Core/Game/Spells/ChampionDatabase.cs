using LoLServer.Core.Game.Combat;

namespace LoLServer.Core.Game.Spells;

/// <summary>
/// Extended champion spell database (50+ champions).
/// Base stats and spell data for the most popular champions.
/// </summary>
public static class ChampionDatabase
{
    /// <summary>
    /// Register all additional champion spell kits into SpellManager.
    /// Call once at startup after SpellManager static init.
    /// </summary>
    public static void RegisterAll(System.Collections.Generic.Dictionary<string, ChampionSpellKit> registry)
    {
        // --- TANKS ---
        registry["Malphite"] = Kit(
            Q("Seismic Shard", DamageType.Magic, D(70,120,170,220,270), 0, 0.6f, CD(8), 625, 70),
            Q("Thunderclap", DamageType.Physical, D(30,45,60,75,90), 0.2f, 0.2f, CD(12,11,10,9,8), 400, 25),
            Q("Ground Slam", DamageType.Magic, D(60,95,130,165,200), 0.6f, 0.4f, CD(7), 400, 50),
            Q("Unstoppable Force", DamageType.Magic, D(200,300,400), 0, 0.9f, CD(130,105,80), 1000, 100));

        registry["Leona"] = Kit(
            Q("Shield of Daybreak", DamageType.Magic, D(10,35,60,85,110), 0, 0.3f, CD(6), 300, 35),
            Q("Eclipse", DamageType.Magic, D(45,80,115,150,185), 0, 0.4f, CD(14,13,12,11,10), 0, 60),
            Q("Zenith Blade", DamageType.Magic, D(50,90,130,170,210), 0, 0.4f, CD(12,10.5f,9,7.5f,6), 875, 60),
            Q("Solar Flare", DamageType.Magic, D(100,175,250), 0, 0.8f, CD(90,75,60), 1200, 100));

        registry["Nautilus"] = Kit(
            Q("Dredge Line", DamageType.Magic, D(70,115,160,205,250), 0, 0.9f, CD(14,13,12,11,10), 1100, 60),
            Q("Titan's Wrath", DamageType.Magic, D(30,40,50,60,70), 0, 0.4f, CD(12), 0, 80),
            Q("Riptide", DamageType.Magic, D(55,85,115,145,175), 0, 0.5f, CD(7,6.5f,6,5.5f,5), 600, 50),
            Q("Depth Charge", DamageType.Magic, D(150,275,400), 0, 0.8f, CD(120,100,80), 825, 100));

        registry["Thresh"] = Kit(
            Q("Death Sentence", DamageType.Magic, D(80,120,160,200,240), 0, 0.5f, CD(20,18,16,14,12), 1100, 70),
            Q("Dark Passage", DamageType.Magic, D(60,100,140,180,220), 0, 0.4f, CD(22,19.5f,17,14.5f,12), 950, 50),
            Q("Flay", DamageType.Magic, D(65,95,125,155,185), 0, 0.4f, CD(9), 400, 60),
            Q("The Box", DamageType.Magic, D(250,400,550), 0, 1.0f, CD(140,120,100), 450, 100));

        // --- ASSASSINS ---
        registry["Zed"] = Kit(
            Q("Razor Shuriken", DamageType.Physical, D(80,115,150,185,220), 1.0f, 0, CD(6), 900, 75),
            Q("Living Shadow", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(22,20,18,16,14), 650, 40),
            Q("Shadow Slash", DamageType.Physical, D(70,90,110,130,150), 0.8f, 0, CD(5,4.5f,4,3.5f,3), 290, 50),
            Q("Death Mark", DamageType.Physical, D(0,0,0), 1.0f, 0, CD(120,90,60), 625, 0));

        registry["Talon"] = Kit(
            Q("Noxian Diplomacy", DamageType.Physical, D(65,85,105,125,145), 1.0f, 0, CD(8,7.5f,7,6.5f,6), 550, 30),
            Q("Rake", DamageType.Physical, D(45,60,75,90,105), 0.4f, 0, CD(9), 900, 55),
            Q("Assassin's Path", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(0), 800, 0),
            Q("Shadow Assault", DamageType.Physical, D(90,135,180), 1.0f, 0, CD(100,80,60), 550, 100));

        registry["Katarina"] = Kit(
            Q("Bouncing Blade", DamageType.Magic, D(75,105,135,165,195), 0, 0.3f, CD(11,10,9,8,7), 625, 0),
            Q("Preparation", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(15,14,13,12,11), 0, 0),
            Q("Shunpo", DamageType.Magic, D(15,30,45,60,75), 0.5f, 0.25f, CD(14,12.5f,11,9.5f,8), 725, 0),
            Q("Death Lotus", DamageType.Magic, D(375,562,750), 2.5f, 2.85f, CD(90,60,45), 550, 0));

        registry["Akali"] = Kit(
            Q("Five Point Strike", DamageType.Magic, D(30,55,80,105,130), 0.6f, 0.6f, CD(1.5f), 500, 110),
            Q("Twilight Shroud", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(20), 0, 0),
            Q("Shuriken Flip", DamageType.Magic, D(30,56,82,108,134), 0.25f, 0.36f, CD(16,14.5f,13,11.5f,10), 825, 30),
            Q("Perfect Execution", DamageType.Magic, D(80,220,360), 0.5f, 0.3f, CD(100,80,60), 675, 0));

        // --- ADC ---
        registry["Caitlyn"] = Kit(
            Q("Piltover Peacemaker", DamageType.Physical, D(50,90,130,170,210), 1.3f, 0, CD(10,9,8,7,6), 1250, 50),
            Q("Yordle Snap Trap", DamageType.Magic, D(30,70,110,150,190), 0, 0.4f, CD(0.5f), 800, 20),
            Q("90 Caliber Net", DamageType.Magic, D(70,110,150,190,230), 0, 0.8f, CD(16,14,12,10,8), 750, 75),
            Q("Ace in the Hole", DamageType.Physical, D(250,475,700), 2.0f, 0, CD(90,75,60), 3500, 100));

        registry["Vayne"] = Kit(
            Q("Tumble", DamageType.Physical, D(0,0,0,0,0), 0.6f, 0, CD(4,3.5f,3,2.5f,2), 300, 30),
            Q("Silver Bolts", DamageType.True, D(0,0,0,0,0), 0, 0, CD(0), 0, 0),
            Q("Condemn", DamageType.Physical, D(50,85,120,155,190), 0.5f, 0, CD(20,18,16,14,12), 550, 90),
            Q("Final Hour", DamageType.Physical, D(0,0,0), 0, 0, CD(100,85,70), 0, 0));

        registry["Kaisa"] = Kit(
            Q("Icathian Rain", DamageType.Physical, D(45,61,77,93,109), 0.5f, 0.25f, CD(10,9,8,7,6), 600, 55),
            Q("Void Seeker", DamageType.Magic, D(30,55,80,105,130), 0.7f, 0.7f, CD(22,20,18,16,14), 3000, 55),
            Q("Supercharge", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(16,14.5f,13,11.5f,10), 0, 30),
            Q("Killer Instinct", DamageType.Magic, D(0,0,0), 0, 0, CD(130,100,70), 1500, 100));

        registry["Jhin"] = Kit(
            Q("Dancing Grenade", DamageType.Physical, D(45,70,95,120,145), 0.4f, 0.6f, CD(7,6.5f,6,5.5f,5), 550, 40),
            Q("Deadly Flourish", DamageType.Physical, D(50,85,120,155,190), 0.5f, 0, CD(14), 2550, 50),
            Q("Captive Audience", DamageType.Magic, D(20,80,140,200,260), 0, 1.2f, CD(2), 750, 30),
            Q("Curtain Call", DamageType.Physical, D(50,125,200), 0.25f, 0, CD(120,105,90), 3500, 100));

        registry["Tristana"] = Kit(
            Q("Rapid Fire", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(20,19,18,17,16), 0, 0),
            Q("Rocket Jump", DamageType.Magic, D(95,145,195,245,295), 0, 0.5f, CD(22,20,18,16,14), 900, 60),
            Q("Explosive Charge", DamageType.Physical, D(70,80,90,100,110), 1.1f, 0.5f, CD(16,15,14,13,12), 525, 70),
            Q("Buster Shot", DamageType.Magic, D(300,400,500), 0, 1.0f, CD(120,110,100), 525, 100));

        // --- MAGES ---
        registry["Veigar"] = Kit(
            Q("Baleful Strike", DamageType.Magic, D(80,120,160,200,240), 0, 0.6f, CD(7,6.5f,6,5.5f,5), 950, 40),
            Q("Dark Matter", DamageType.Magic, D(100,150,200,250,300), 0, 1.0f, CD(8), 900, 60),
            Q("Event Horizon", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(18,16.5f,15,13.5f,12), 700, 70),
            Q("Primordial Burst", DamageType.Magic, D(175,250,325), 0, 0.75f, CD(120,100,80), 650, 100));

        registry["Syndra"] = Kit(
            Q("Dark Sphere", DamageType.Magic, D(70,105,140,175,210), 0, 0.65f, CD(4), 800, 40),
            Q("Force of Will", DamageType.Magic, D(70,110,150,190,230), 0, 0.7f, CD(12,11,10,9,8), 950, 60),
            Q("Scatter the Weak", DamageType.Magic, D(85,130,175,220,265), 0, 0.6f, CD(16,15,14,13,12), 700, 50),
            Q("Unleashed Power", DamageType.Magic, D(270,405,540), 0, 0.6f, CD(120,100,80), 675, 100));

        registry["Orianna"] = Kit(
            Q("Command: Attack", DamageType.Magic, D(60,90,120,150,180), 0, 0.5f, CD(6,5.25f,4.5f,3.75f,3), 825, 30),
            Q("Command: Dissonance", DamageType.Magic, D(60,105,150,195,240), 0, 0.7f, CD(7), 0, 70),
            Q("Command: Protect", DamageType.Magic, D(60,90,120,150,180), 0, 0.3f, CD(9), 1100, 60),
            Q("Command: Shockwave", DamageType.Magic, D(200,275,350), 0, 0.9f, CD(110,95,80), 0, 100));

        registry["Viktor"] = Kit(
            Q("Siphon Power", DamageType.Magic, D(60,75,90,105,120), 0, 0.4f, CD(9,8,7,6,5), 600, 45),
            Q("Gravity Field", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(17,16,15,14,13), 800, 65),
            Q("Death Ray", DamageType.Magic, D(70,110,150,190,230), 0, 0.5f, CD(12,11,10,9,8), 525, 70),
            Q("Chaos Storm", DamageType.Magic, D(100,175,250), 0, 0.5f, CD(120,100,80), 700, 100));

        // --- BRUISERS / FIGHTERS ---
        registry["Jax"] = Kit(
            Q("Leap Strike", DamageType.Physical, D(65,105,145,185,225), 1.0f, 0.6f, CD(8,7.5f,7,6.5f,6), 700, 65),
            Q("Empower", DamageType.Magic, D(40,75,110,145,180), 0, 0.6f, CD(7,6,5,4,3), 300, 30),
            Q("Counter Strike", DamageType.Physical, D(55,80,105,130,155), 0.5f, 0, CD(16,14,12,10,8), 300, 50),
            Q("Grandmaster's Might", DamageType.Magic, D(100,160,220), 0, 0.7f, CD(80), 0, 100));

        registry["Irelia"] = Kit(
            Q("Bladesurge", DamageType.Physical, D(5,25,45,65,85), 0.6f, 0, CD(11,10,9,8,7), 600, 20),
            Q("Defiant Dance", DamageType.Physical, D(10,25,40,55,70), 0, 0.5f, CD(20,18,16,14,12), 825, 70),
            Q("Flawless Duet", DamageType.Magic, D(80,125,170,215,260), 0, 0.8f, CD(16,15,14,13,12), 775, 50),
            Q("Vanguard's Edge", DamageType.Magic, D(125,225,325), 0, 0.7f, CD(140,120,100), 1000, 100));

        registry["Fiora"] = Kit(
            Q("Lunge", DamageType.Physical, D(70,80,90,100,110), 1.0f, 0, CD(13,11,9,7,5), 400, 20),
            Q("Riposte", DamageType.Magic, D(110,150,190,230,270), 0, 1.0f, CD(24,22,20,18,16), 750, 50),
            Q("Bladework", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(13,11,9,7,5), 0, 40),
            Q("Grand Challenge", DamageType.True, D(0,0,0), 0, 0, CD(110,90,70), 500, 100));

        registry["Camille"] = Kit(
            Q("Precision Protocol", DamageType.Physical, D(20,25,30,35,40), 1.0f, 0, CD(9,8,7,6,5), 300, 25),
            Q("Tactical Sweep", DamageType.Physical, D(70,100,130,160,190), 0.7f, 0, CD(15,13.5f,12,10.5f,9), 610, 50),
            Q("Hookshot", DamageType.Physical, D(60,95,130,165,200), 0.75f, 0, CD(16,14.5f,13,11.5f,10), 800, 70),
            Q("The Hextech Ultimatum", DamageType.Magic, D(5,10,15), 0.04f, 0, CD(140,115,90), 475, 100));

        registry["Renekton"] = Kit(
            Q("Cull the Meek", DamageType.Physical, D(65,100,135,170,205), 0.8f, 0, CD(8), 325, 0),
            Q("Ruthless Predator", DamageType.Physical, D(10,30,50,70,90), 1.5f, 0, CD(13,12,11,10,9), 300, 0),
            Q("Slice and Dice", DamageType.Physical, D(40,70,100,130,160), 0.9f, 0, CD(16,14,12,10,8), 450, 0),
            Q("Dominus", DamageType.Magic, D(50,100,150), 0, 0.1f, CD(120), 175, 0));

        // --- SUPPORTS ---
        registry["Lulu"] = Kit(
            Q("Glitterlance", DamageType.Magic, D(70,105,140,175,210), 0, 0.5f, CD(7), 925, 50),
            Q("Whimsy", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(17,16,15,14,13), 650, 65),
            Q("Help, Pix!", DamageType.Magic, D(80,120,160,200,240), 0, 0.4f, CD(8), 650, 60),
            Q("Wild Growth", DamageType.Magic, D(0,0,0), 0, 0, CD(110,95,80), 900, 100));

        registry["Nami"] = Kit(
            Q("Aqua Prison", DamageType.Magic, D(75,130,185,240,295), 0, 0.5f, CD(12,11,10,9,8), 875, 60),
            Q("Ebb and Flow", DamageType.Magic, D(70,110,150,190,230), 0, 0.5f, CD(10), 725, 70),
            Q("Tidecaller's Blessing", DamageType.Magic, D(25,40,55,70,85), 0, 0.2f, CD(11,10,9,8,7), 800, 55),
            Q("Tidal Wave", DamageType.Magic, D(150,250,350), 0, 0.6f, CD(120,110,100), 2750, 100));

        registry["Soraka"] = Kit(
            Q("Starcall", DamageType.Magic, D(85,120,155,190,225), 0, 0.35f, CD(8,7,6,5,4), 810, 45),
            Q("Astral Infusion", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(6,5,4,3,2), 550, 40),
            Q("Equinox", DamageType.Magic, D(70,95,120,145,170), 0, 0.4f, CD(24,22,20,18,16), 925, 70),
            Q("Wish", DamageType.Magic, D(150,250,350), 0, 0.5f, CD(160,145,130), 99999, 0));

        // --- MISC POPULAR ---
        registry["Teemo"] = Kit(
            Q("Blinding Dart", DamageType.Magic, D(80,125,170,215,260), 0, 0.8f, CD(8), 680, 70),
            Q("Move Quick", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(17), 0, 40),
            Q("Toxic Shot", DamageType.Magic, D(11,22,33,44,55), 0, 0.3f, CD(0), 0, 0),
            Q("Noxious Trap", DamageType.Magic, D(200,325,450), 0, 0.5f, CD(30,25,20), 400, 75));

        registry["LeeSin"] = Kit(
            Q("Sonic Wave", DamageType.Physical, D(55,80,105,130,155), 1.0f, 0, CD(11,10,9,8,7), 1200, 50),
            Q("Safeguard", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(14), 700, 50),
            Q("Tempest", DamageType.Physical, D(35,65,95,125,155), 1.0f, 0, CD(10), 350, 50),
            Q("Dragon's Rage", DamageType.Physical, D(175,400,625), 2.0f, 0, CD(90,75,60), 375, 0));

        registry["Morgana"] = Kit(
            Q("Dark Binding", DamageType.Magic, D(80,135,190,245,300), 0, 0.9f, CD(11), 1175, 50),
            Q("Tormented Shadow", DamageType.Magic, D(12,22,32,42,52), 0, 0.14f, CD(12), 900, 70),
            Q("Black Shield", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(26,24,22,20,18), 800, 80),
            Q("Soul Shackles", DamageType.Magic, D(175,250,325), 0, 0.8f, CD(120,110,100), 625, 100));

        registry["Blitzcrank"] = Kit(
            Q("Rocket Grab", DamageType.Magic, D(70,120,170,220,270), 0, 1.0f, CD(20,19,18,17,16), 1150, 100),
            Q("Overdrive", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(15), 0, 75),
            Q("Power Fist", DamageType.Physical, D(0,0,0,0,0), 1.0f, 0, CD(9,8,7,6,5), 300, 25),
            Q("Static Field", DamageType.Magic, D(250,375,500), 0, 1.0f, CD(90,75,60), 600, 100));
    }

    // Helper aliases to keep registration compact
    private static float[] D(params float[] vals) => vals;
    private static float[] CD(params float[] vals) => vals;
    private static float[] CD(float v) => new[] { v, v, v, v, v };

    private static SpellData Q(string name, DamageType dt, float[] dmg, float ad, float ap, float[] cd, float range, float mana)
        => new(name, dt, dmg, ad, ap, cd, range, mana);

    private static ChampionSpellKit Kit(SpellData q, SpellData w, SpellData e, SpellData r)
        => new() { Q = q, W = w, E = e, R = r };
}
