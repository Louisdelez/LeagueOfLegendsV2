using LoLServer.Core.Game.Combat;

namespace LoLServer.Core.Game.Spells;

/// <summary>
/// Extended champion database part 5: S-Z champions.
/// Samira, Sejuani, Senna, Seraphine, Sett, Shaco, Shen, Shyvana,
/// Singed, Sion, Sivir, Skarner, Smolder, Sona, Swain, Sylas,
/// TahmKench, Taliyah, Taric, Twitch, Trundle, Tryndamere,
/// TwistedFate, Udyr, Urgot, Varus, Vel'Koz, Vex, Vi,
/// Viego, Vladimir, Volibear, Warwick, Wukong, Xayah,
/// Xerath, XinZhao, Yone, Yorick, Yuumi, Zac, Zeri, Ziggs, Zilean, Zoe, Zyra
/// </summary>
public static class ChampionDatabase5
{
    public static void RegisterAll(System.Collections.Generic.Dictionary<string, ChampionSpellKit> registry)
    {
        registry["Samira"] = Kit(
            Q("Flair", DamageType.Physical, D(0,5,10,15,20), 0.9f, 0, CD(6,5,4,3,2), 950, 30),
            Q("Blade Whirl", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(30,28,26,24,22), 325, 0),
            Q("Wild Rush", DamageType.Physical, D(50,60,70,80,90), 0.2f, 0, CD(20,18,16,14,12), 600, 40),
            Q("Inferno Trigger", DamageType.Physical, D(0,0,0), 0.6f, 0, CD(8,6,4), 600, 0));

        registry["Sejuani"] = Kit(
            Q("Arctic Assault", DamageType.Magic, D(90,140,190,240,290), 0, 0.6f, CD(18,16.5f,15,13.5f,12), 650, 70),
            Q("Winter's Wrath", DamageType.Physical, D(20,25,30,35,40), 0.2f, 0, CD(9,8.25f,7.5f,6.75f,6), 600, 65),
            Q("Permafrost", DamageType.Magic, D(40,80,120,160,200), 0, 0.6f, CD(1.5f), 0, 20),
            Q("Glacial Prison", DamageType.Magic, D(125,150,175), 0, 0.4f, CD(120,100,80), 1300, 100));

        registry["Senna"] = Kit(
            Q("Piercing Darkness", DamageType.Physical, D(40,70,100,130,160), 0.5f, 0, CD(15,14,13,12,11), 1300, 70),
            Q("Last Embrace", DamageType.Physical, D(70,115,160,205,250), 0.7f, 0, CD(11,10,9,8,7), 1150, 55),
            Q("Curse of the Black Mist", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(22,20,18,16,14), 0, 50),
            Q("Dawning Shadow", DamageType.Physical, D(250,375,500), 1.0f, 0.5f, CD(160,140,120), 99999, 100));

        registry["Seraphine"] = Kit(
            Q("High Note", DamageType.Magic, D(55,70,85,100,115), 0, 0.45f, CD(10,8.75f,7.5f,6.25f,5), 900, 65),
            Q("Surround Sound", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(28,26,24,22,20), 0, 50),
            Q("Beat Drop", DamageType.Magic, D(60,80,100,120,140), 0, 0.35f, CD(13,12,11,10,9), 1300, 60),
            Q("Encore", DamageType.Magic, D(150,200,250), 0, 0.6f, CD(160,130,100), 1200, 100));

        registry["Sett"] = Kit(
            Q("Knuckle Down", DamageType.Physical, D(10,20,30,40,50), 0.01f, 0, CD(9,8,7,6,5), 300, 0),
            Q("Haymaker", DamageType.True, D(80,100,120,140,160), 0, 0.2f, CD(18,16.5f,15,13.5f,12), 790, 0),
            Q("Facebreaker", DamageType.Physical, D(50,70,90,110,130), 0.5f, 0, CD(16,14.5f,13,11.5f,10), 490, 0),
            Q("The Show Stopper", DamageType.Physical, D(99,198,297), 1.0f, 0, CD(120,100,80), 400, 0));

        registry["Shaco"] = Kit(
            Q("Deceive", DamageType.Physical, D(25,35,45,55,65), 0.5f, 0, CD(12,11.5f,11,10.5f,10), 400, 60),
            Q("Jack In The Box", DamageType.Magic, D(35,50,65,80,95), 0, 0.2f, CD(16), 500, 50),
            Q("Two-Shiv Poison", DamageType.Physical, D(70,95,120,145,170), 0.7f, 0.55f, CD(8), 625, 65),
            Q("Hallucinate", DamageType.Magic, D(150,225,300), 1.0f, 1.0f, CD(100,80,60), 0, 100));

        registry["Shen"] = Kit(
            Q("Spirit Blade", DamageType.Magic, D(10,16,22,28,34), 0, 0.02f, CD(8,7.25f,6.5f,5.75f,5), 0, 0),
            Q("Spirit's Refuge", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(18,16.5f,15,13.5f,12), 0, 0),
            Q("Shadow Dash", DamageType.Physical, D(60,85,110,135,160), 0.15f, 0, CD(18,16,14,12,10), 600, 150),
            Q("Stand United", DamageType.Magic, D(0,0,0), 0, 0, CD(200,180,160), 99999, 0));

        registry["Shyvana"] = Kit(
            Q("Twin Bite", DamageType.Physical, D(20,35,50,65,80), 1.0f, 0, CD(9,8,7,6,5), 300, 0),
            Q("Burnout", DamageType.Magic, D(20,33,45,58,70), 0.15f, 0, CD(12), 325, 0),
            Q("Flame Breath", DamageType.Magic, D(60,100,140,180,220), 0.3f, 0.7f, CD(12,11,10,9,8), 925, 0),
            Q("Dragon's Descent", DamageType.Magic, D(150,250,350), 1.0f, 1.0f, CD(100), 850, 0));

        registry["Singed"] = Kit(
            Q("Poison Trail", DamageType.Magic, D(22,34,46,58,70), 0, 0.3f, CD(0), 0, 13),
            Q("Mega Adhesive", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(17,16,15,14,13), 1000, 60),
            Q("Fling", DamageType.Magic, D(50,65,80,95,110), 0, 0.6f, CD(10,9.5f,9,8.5f,8), 125, 80),
            Q("Insanity Potion", DamageType.Magic, D(0,0,0), 0, 0, CD(120,110,100), 0, 100));

        registry["Sion"] = Kit(
            Q("Decimating Smash", DamageType.Physical, D(30,50,70,90,110), 0.45f, 0, CD(10,9,8,7,6), 600, 45),
            Q("Soul Furnace", DamageType.Magic, D(40,65,90,115,140), 0, 0.4f, CD(15,14,13,12,11), 550, 65),
            Q("Roar of the Slayer", DamageType.Magic, D(65,100,135,170,205), 0, 0.55f, CD(12,11,10,9,8), 800, 35),
            Q("Unstoppable Onslaught", DamageType.Physical, D(150,300,450), 0.8f, 0, CD(140,100,60), 99999, 100));

        registry["Sivir"] = Kit(
            Q("Boomerang Blade", DamageType.Physical, D(25,40,55,70,85), 0.8f, 0.6f, CD(7), 1250, 55),
            Q("Ricochet", DamageType.Physical, D(0,0,0,0,0), 0.3f, 0, CD(12,10.5f,9,7.5f,6), 0, 60),
            Q("Spell Shield", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(22,19,16,13,10), 0, 0),
            Q("On the Hunt", DamageType.Physical, D(0,0,0), 0, 0, CD(120,100,80), 0, 100));

        registry["Skarner"] = Kit(
            Q("Shattered Earth", DamageType.Physical, D(10,15,20,25,30), 0.4f, 0.15f, CD(3.5f,3.25f,3,2.75f,2.5f), 350, 0),
            Q("Seismic Bastion", DamageType.Magic, D(60,90,120,150,180), 0, 0.8f, CD(11,10.5f,10,9.5f,9), 0, 0),
            Q("Ixtal's Impact", DamageType.Physical, D(30,50,70,90,110), 0.6f, 0.5f, CD(14,13,12,11,10), 600, 0),
            Q("Impale", DamageType.Physical, D(60,100,140), 0.5f, 0, CD(130,110,90), 500, 0));

        registry["Smolder"] = Kit(
            Q("Super Scorcher Breath", DamageType.Physical, D(15,25,35,45,55), 1.0f, 0.5f, CD(5.5f,5,4.5f,4,3.5f), 550, 25),
            Q("Achooo!", DamageType.Physical, D(50,70,90,110,130), 0.5f, 0.35f, CD(14,13,12,11,10), 1050, 60),
            Q("Flap, Flap, Flap", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(22,20,18,16,14), 550, 0),
            Q("MMOOOMMMM!", DamageType.Physical, D(150,250,350), 1.0f, 0.5f, CD(140,120,100), 3500, 100));

        registry["Sona"] = Kit(
            Q("Hymn of Valor", DamageType.Magic, D(50,80,110,140,170), 0, 0.4f, CD(8), 825, 50),
            Q("Aria of Perseverance", DamageType.Magic, D(30,50,70,90,110), 0, 0.2f, CD(10), 1000, 80),
            Q("Song of Celerity", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(14), 0, 65),
            Q("Crescendo", DamageType.Magic, D(150,250,350), 0, 0.5f, CD(140,120,100), 900, 100));

        registry["Swain"] = Kit(
            Q("Death's Hand", DamageType.Magic, D(60,80,100,120,140), 0, 0.38f, CD(9,7.5f,6,4.5f,3), 725, 65),
            Q("Vision of Empire", DamageType.Magic, D(80,120,160,200,240), 0, 0.55f, CD(22,21,20,19,18), 5500, 70),
            Q("Nevermove", DamageType.Magic, D(35,70,105,140,175), 0, 0.25f, CD(10), 900, 50),
            Q("Demonic Ascension", DamageType.Magic, D(20,40,60), 0, 0.05f, CD(120), 650, 100));

        registry["Sylas"] = Kit(
            Q("Chain Lash", DamageType.Magic, D(40,55,70,85,100), 0, 0.4f, CD(10,9,8,7,6), 775, 55),
            Q("Kingslayer", DamageType.Magic, D(65,100,135,170,205), 0.4f, 0.9f, CD(14,13,12,11,10), 400, 70),
            Q("Abscond/Abduct", DamageType.Magic, D(80,130,180,230,280), 0, 0.8f, CD(14,13,12,11,10), 800, 65),
            Q("Hijack", DamageType.Magic, D(0,0,0), 0, 0, CD(100,70,40), 950, 75));

        registry["TahmKench"] = Kit(
            Q("Tongue Lash", DamageType.Magic, D(80,130,180,230,280), 0, 0.7f, CD(7,6.5f,6,5.5f,5), 900, 50),
            Q("Abyssal Dive", DamageType.Magic, D(80,135,190,245,300), 0, 1.0f, CD(21,20,19,18,17), 1200, 60),
            Q("Thick Skin", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(3), 0, 0),
            Q("Devour", DamageType.Magic, D(100,250,400), 0, 0.15f, CD(120,100,80), 250, 100));

        registry["Taliyah"] = Kit(
            Q("Threaded Volley", DamageType.Magic, D(38,61,84,107,130), 0, 0.5f, CD(7,6,5,4,3), 1000, 55),
            Q("Seismic Shove", DamageType.Magic, D(60,80,100,120,140), 0, 0.4f, CD(16,15,14,13,12), 900, 40),
            Q("Unraveled Earth", DamageType.Magic, D(50,75,100,125,150), 0, 0.4f, CD(16,14,12,10,8), 800, 90),
            Q("Weaver's Wall", DamageType.Magic, D(0,0,0), 0, 0, CD(180,150,120), 3000, 100));

        registry["Taric"] = Kit(
            Q("Starlight's Touch", DamageType.Magic, D(30,40,50,60,70), 0, 0.15f, CD(3), 0, 70),
            Q("Bastion", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(15), 800, 60),
            Q("Dazzle", DamageType.Magic, D(90,130,170,210,250), 0, 0.5f, CD(17,16,15,14,13), 575, 60),
            Q("Cosmic Radiance", DamageType.Magic, D(0,0,0), 0, 0, CD(180,150,120), 0, 100));

        registry["Twitch"] = Kit(
            Q("Ambush", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(16), 0, 40),
            Q("Venom Cask", DamageType.Physical, D(35,50,65,80,95), 0, 0.2f, CD(13,12,11,10,9), 950, 70),
            Q("Contaminate", DamageType.Physical, D(20,30,40,50,60), 0.35f, 0.2f, CD(12,11,10,9,8), 1200, 50),
            Q("Spray and Pray", DamageType.Physical, D(0,0,0), 0, 0, CD(90), 0, 100));

        registry["Trundle"] = Kit(
            Q("Chomp", DamageType.Physical, D(20,40,60,80,100), 0.15f, 0, CD(4), 300, 30),
            Q("Frozen Domain", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(18,17,16,15,14), 0, 0),
            Q("Pillar of Ice", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(24,22,20,18,16), 1000, 75),
            Q("Subjugate", DamageType.Magic, D(20,27.5f,35), 0.02f, 0, CD(120,100,80), 650, 75));

        registry["Tryndamere"] = Kit(
            Q("Bloodlust", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(12,11,10,9,8), 0, 0),
            Q("Mocking Shout", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(14), 850, 0),
            Q("Spinning Slash", DamageType.Physical, D(80,110,140,170,200), 1.3f, 1.0f, CD(12,11,10,9,8), 660, 0),
            Q("Undying Rage", DamageType.Physical, D(0,0,0), 0, 0, CD(110,100,90), 0, 0));

        registry["TwistedFate"] = Kit(
            Q("Wild Cards", DamageType.Magic, D(60,105,150,195,240), 0, 0.65f, CD(6), 1450, 60),
            Q("Pick a Card", DamageType.Magic, D(40,60,80,100,120), 0, 0.5f, CD(8,7.5f,7,6.5f,6), 525, 40),
            Q("Stacked Deck", DamageType.Magic, D(65,90,115,140,165), 0, 0.5f, CD(0), 525, 0),
            Q("Destiny", DamageType.Magic, D(0,0,0), 0, 0, CD(150,130,110), 5500, 100));

        registry["Udyr"] = Kit(
            Q("Wilding Claw", DamageType.Physical, D(20,40,60,80,100), 0.1f, 0.8f, CD(6), 300, 45),
            Q("Iron Mantle", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(6), 0, 45),
            Q("Blazing Stampede", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(6), 0, 45),
            Q("Wingborne Storm", DamageType.Magic, D(20,38,56,74,92), 0, 0.35f, CD(6), 0, 45));

        registry["Urgot"] = Kit(
            Q("Corrosive Charge", DamageType.Physical, D(25,70,115,160,205), 0.7f, 0, CD(12,11,10,9,8), 800, 80),
            Q("Purge", DamageType.Physical, D(12,20,28,36,44), 0.2f, 0, CD(17,15,13,11,9), 490, 45),
            Q("Disdain", DamageType.Physical, D(90,120,150,180,210), 0.5f, 0, CD(16,15.5f,15,14.5f,14), 475, 50),
            Q("Fear Beyond Death", DamageType.Physical, D(100,225,350), 0.5f, 0, CD(120,95,70), 2500, 100));

        registry["Varus"] = Kit(
            Q("Piercing Arrow", DamageType.Physical, D(10,47,83,120,157), 1.3f, 1.0f, CD(16,15,14,13,12), 925, 70),
            Q("Blighted Quiver", DamageType.Magic, D(7,10.5f,14,17.5f,21), 0, 0.25f, CD(0), 0, 0),
            Q("Hail of Arrows", DamageType.Physical, D(60,100,140,180,220), 0.6f, 0, CD(18,16,14,12,10), 925, 80),
            Q("Chain of Corruption", DamageType.Magic, D(150,250,350), 0, 1.0f, CD(100,80,60), 1200, 100));

        registry["VelKoz"] = Kit(
            Q("Plasma Fission", DamageType.Magic, D(80,120,160,200,240), 0, 0.8f, CD(7,6.5f,6,5.5f,5), 1050, 40),
            Q("Void Rift", DamageType.Magic, D(30,50,70,90,110), 0, 0.15f, CD(1.5f), 1050, 50),
            Q("Tectonic Disruption", DamageType.Magic, D(70,100,130,160,190), 0, 0.3f, CD(16,15,14,13,12), 850, 50),
            Q("Lifeform Disintegration Ray", DamageType.Magic, D(450,625,800), 0, 1.25f, CD(120,100,80), 1550, 100));

        registry["Vex"] = Kit(
            Q("Mistral Bolt", DamageType.Magic, D(60,105,150,195,240), 0, 0.7f, CD(9,8,7,6,5), 1200, 45),
            Q("Personal Space", DamageType.Magic, D(80,120,160,200,240), 0, 0.6f, CD(20,18,16,14,12), 475, 75),
            Q("Looming Darkness", DamageType.Magic, D(50,70,90,110,130), 0, 0.4f, CD(13), 800, 70),
            Q("Shadow Surge", DamageType.Magic, D(75,125,175), 0, 0.2f, CD(140,110,80), 2000, 100));

        registry["Vi"] = Kit(
            Q("Vault Breaker", DamageType.Physical, D(55,80,105,130,155), 0.7f, 0, CD(12,10.5f,9,7.5f,6), 725, 0),
            Q("Blast Shield", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(12,11,10,9,8), 0, 0),
            Q("Relentless Force", DamageType.Physical, D(10,30,50,70,90), 0.7f, 0.9f, CD(1), 0, 26),
            Q("Cease and Desist", DamageType.Physical, D(150,325,500), 1.1f, 0, CD(120,100,80), 800, 100));

        registry["Viego"] = Kit(
            Q("Blade of the Ruined King", DamageType.Physical, D(25,40,55,70,85), 0.6f, 0, CD(5,4.5f,4,3.5f,3), 600, 0),
            Q("Spectral Maw", DamageType.Magic, D(80,135,190,245,300), 0, 1.0f, CD(8), 500, 0),
            Q("Harrowed Path", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(14,12,10,8,6), 775, 0),
            Q("Heartbreaker", DamageType.Physical, D(0,0,0), 0, 0, CD(120,100,80), 300, 0));

        registry["Vladimir"] = Kit(
            Q("Transfusion", DamageType.Magic, D(80,100,120,140,160), 0, 0.6f, CD(9,8,7,6,5), 600, 0),
            Q("Sanguine Pool", DamageType.Magic, D(20,33.75f,47.5f,61.25f,75), 0, 0.15f, CD(28,25,22,19,16), 350, 0),
            Q("Tides of Blood", DamageType.Magic, D(30,45,60,75,90), 0, 0.35f, CD(13,11,9,7,5), 600, 0),
            Q("Hemoplague", DamageType.Magic, D(150,250,350), 0, 0.7f, CD(150,135,120), 700, 0));

        registry["Volibear"] = Kit(
            Q("Thundering Smash", DamageType.Physical, D(20,40,60,80,100), 1.2f, 0, CD(14,13,12,11,10), 0, 50),
            Q("Frenzied Maul", DamageType.Physical, D(5,30,55,80,105), 1.0f, 0.8f, CD(5), 325, 40),
            Q("Sky Splitter", DamageType.Magic, D(80,110,140,170,200), 0, 0.8f, CD(15), 1200, 60),
            Q("Stormbringer", DamageType.Physical, D(300,500,700), 2.5f, 1.25f, CD(160,140,120), 700, 0));

        registry["Warwick"] = Kit(
            Q("Jaws of the Beast", DamageType.Magic, D(120,150,180,210,240), 0, 0.9f, CD(6,5.5f,5,4.5f,4), 350, 0),
            Q("Blood Hunt", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(120,110,100,90,80), 0, 70),
            Q("Primal Howl", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(15,14,13,12,11), 0, 40),
            Q("Infinite Duress", DamageType.Magic, D(175,350,525), 1.67f, 0, CD(110,90,70), 3000, 0));

        registry["Wukong"] = Kit(
            Q("Crushing Blow", DamageType.Physical, D(30,55,80,105,130), 0.5f, 0, CD(8,7.5f,7,6.5f,6), 300, 40),
            Q("Warrior Trickster", DamageType.Magic, D(70,110,150,190,230), 0, 0.6f, CD(22,19,16,13,10), 0, 80),
            Q("Nimbus Strike", DamageType.Physical, D(80,110,140,170,200), 0.8f, 0.8f, CD(10,9,8,7,6), 625, 30),
            Q("Cyclone", DamageType.Physical, D(0,0,0), 1.1f, 0, CD(120,105,90), 0, 100));

        registry["Xayah"] = Kit(
            Q("Double Daggers", DamageType.Physical, D(45,60,75,90,105), 0.5f, 0, CD(10,9,8,7,6), 1100, 50),
            Q("Deadly Plumage", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(20,19,18,17,16), 1000, 60),
            Q("Bladecaller", DamageType.Physical, D(55,65,75,85,95), 0.6f, 0, CD(12,11,10,9,8), 0, 40),
            Q("Featherstorm", DamageType.Physical, D(200,300,400), 1.0f, 0, CD(140,120,100), 1100, 100));

        registry["Xerath"] = Kit(
            Q("Arcanopulse", DamageType.Magic, D(70,110,150,190,230), 0, 0.85f, CD(12,11,10,9,8), 1400, 80),
            Q("Eye of Destruction", DamageType.Magic, D(60,90,120,150,180), 0, 0.6f, CD(14,13,12,11,10), 1100, 70),
            Q("Shocking Orb", DamageType.Magic, D(80,110,140,170,200), 0, 0.45f, CD(13,12.5f,12,11.5f,11), 1050, 60),
            Q("Rite of the Arcane", DamageType.Magic, D(200,250,300), 0, 0.45f, CD(130,115,100), 5000, 100));

        registry["XinZhao"] = Kit(
            Q("Three Talon Strike", DamageType.Physical, D(15,30,45,60,75), 0.4f, 0, CD(7,6.5f,6,5.5f,5), 300, 30),
            Q("Wind Becomes Lightning", DamageType.Physical, D(30,40,50,60,70), 0.8f, 0.5f, CD(12,11,10,9,8), 900, 45),
            Q("Audacious Charge", DamageType.Magic, D(50,75,100,125,150), 0, 0.6f, CD(11), 650, 50),
            Q("Crescent Guard", DamageType.Physical, D(75,175,275), 1.0f, 1.1f, CD(120,110,100), 0, 100));

        registry["Yone"] = Kit(
            Q("Mortal Steel", DamageType.Physical, D(20,40,60,80,100), 1.05f, 0, CD(4,3.67f,3.33f,3,2.67f), 475, 0),
            Q("Spirit Cleave", DamageType.Magic, D(10,20,30,40,50), 0, 0, CD(14), 600, 0),
            Q("Soul Unbound", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(21,19,17,15,13), 300, 0),
            Q("Fate Sealed", DamageType.Physical, D(200,400,600), 0.8f, 0, CD(120,90,60), 1000, 0));

        registry["Yorick"] = Kit(
            Q("Last Rites", DamageType.Physical, D(30,55,80,105,130), 0.4f, 0, CD(7,6.25f,5.5f,4.75f,4), 300, 25),
            Q("Dark Procession", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(12,11,10,9,8), 600, 0),
            Q("Mourning Mist", DamageType.Magic, D(15,15,15,15,15), 0, 0.2f, CD(12,11,10,9,8), 700, 0),
            Q("Eulogy of the Isles", DamageType.Physical, D(0,0,0), 0, 0, CD(160,130,100), 600, 100));

        registry["Yuumi"] = Kit(
            Q("Prowling Projectile", DamageType.Magic, D(60,90,120,150,180,210), 0, 0.2f, CD(13.5f,12,10.5f,9,7.5f), 1150, 50),
            Q("You and Me!", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(0.5f), 700, 0),
            Q("Zoomies", DamageType.Magic, D(70,90,110,130,150), 0, 0.15f, CD(12,11,10,9,8), 0, 40),
            Q("Final Chapter", DamageType.Magic, D(60,100,140), 0, 0.2f, CD(130,110,90), 1100, 100));

        registry["Zac"] = Kit(
            Q("Stretching Strikes", DamageType.Magic, D(40,55,70,85,100), 0, 0.3f, CD(13,12,11,10,9), 800, 0),
            Q("Unstable Matter", DamageType.Magic, D(35,50,65,80,95), 0, 0.04f, CD(5), 350, 0),
            Q("Elastic Slingshot", DamageType.Magic, D(60,105,150,195,240), 0, 0.9f, CD(24,21,18,15,12), 1800, 0),
            Q("Let's Bounce!", DamageType.Magic, D(140,210,280), 0, 0.9f, CD(130,115,100), 300, 0));

        registry["Zeri"] = Kit(
            Q("Burst Fire", DamageType.Physical, D(10,15,20,25,30), 1.1f, 0, CD(0), 825, 0),
            Q("Ultrashock Laser", DamageType.Magic, D(40,75,110,145,180), 0, 0.6f, CD(13,12,11,10,9), 1200, 60),
            Q("Spark Surge", DamageType.Physical, D(0,0,0,0,0), 0, 0, CD(23,21.5f,20,18.5f,17), 300, 90),
            Q("Lightning Crash", DamageType.Magic, D(175,275,375), 0, 0.8f, CD(100,85,70), 825, 100));

        registry["Ziggs"] = Kit(
            Q("Bouncing Bomb", DamageType.Magic, D(85,130,175,220,265), 0, 0.65f, CD(6,5.5f,5,4.5f,4), 1400, 50),
            Q("Satchel Charge", DamageType.Magic, D(70,105,140,175,210), 0, 0.5f, CD(20,18,16,14,12), 1000, 65),
            Q("Hexplosive Minefield", DamageType.Magic, D(40,75,110,145,180), 0, 0.3f, CD(16), 900, 70),
            Q("Mega Inferno Bomb", DamageType.Magic, D(200,300,400), 0, 0.7334f, CD(120,105,90), 5300, 100));

        registry["Zilean"] = Kit(
            Q("Time Bomb", DamageType.Magic, D(75,115,165,230,300), 0, 0.9f, CD(10,9.5f,9,8.5f,8), 900, 60),
            Q("Rewind", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(14,12,10,8,6), 0, 35),
            Q("Time Warp", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(15), 550, 50),
            Q("Chronoshift", DamageType.Magic, D(600,850,1100), 0, 2.0f, CD(120,90,60), 900, 125));

        registry["Zoe"] = Kit(
            Q("Paddle Star", DamageType.Magic, D(50,75,100,125,150), 0, 0.6f, CD(8.5f,8,7.5f,7,6.5f), 800, 40),
            Q("Spell Thief", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(0.25f), 550, 0),
            Q("Sleepy Trouble Bubble", DamageType.Magic, D(60,100,140,180,220), 0, 0.45f, CD(16,15,14,13,12), 800, 80),
            Q("Portal Jump", DamageType.Magic, D(0,0,0), 0, 0, CD(11,8,5), 575, 40));

        registry["Zyra"] = Kit(
            Q("Deadly Spines", DamageType.Magic, D(60,95,130,165,200), 0, 0.6f, CD(7,6.5f,6,5.5f,5), 800, 70),
            Q("Rampant Growth", DamageType.Magic, D(0,0,0,0,0), 0, 0, CD(0), 850, 0),
            Q("Grasping Roots", DamageType.Magic, D(60,95,130,165,200), 0, 0.5f, CD(12), 1100, 70),
            Q("Stranglethorns", DamageType.Magic, D(180,265,350), 0, 0.7f, CD(110,100,90), 700, 100));

        // === MISSING FROM FIRST DB: Ambessa ===
        registry["Ambessa"] = Kit(
            Q("Cunning Sweep", DamageType.Physical, D(60,90,120,150,180), 0.85f, 0, CD(7,6.5f,6,5.5f,5), 400, 0),
            Q("Repudiation", DamageType.Physical, D(50,80,110,140,170), 0.6f, 0, CD(14,13,12,11,10), 550, 0),
            Q("Lacerate", DamageType.Physical, D(40,70,100,130,160), 0.7f, 0, CD(12,11,10,9,8), 500, 0),
            Q("Public Execution", DamageType.Physical, D(150,275,400), 1.2f, 0, CD(120,100,80), 650, 0));
    }

    private static float[] D(params float[] vals) => vals;
    private static float[] CD(params float[] vals) => vals;
    private static float[] CD(float v) => new[] { v, v, v, v, v };
    private static SpellData Q(string name, DamageType dt, float[] dmg, float ad, float ap, float[] cd, float range, float mana)
        => new(name, dt, dmg, ad, ap, cd, range, mana);
    private static ChampionSpellKit Kit(SpellData q, SpellData w, SpellData e, SpellData r)
        => new() { Q = q, W = w, E = e, R = r };
}
