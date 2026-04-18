use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct ChampionInfo {
    pub name: String,
    pub display_name: String,
}

#[derive(Serialize, Clone)]
pub struct MapInfo {
    pub id: u32,
    pub name: String,
    pub players: String,
}

#[derive(Serialize, Clone)]
pub struct SpellInfo {
    pub name: String,
    pub display_name: String,
}

pub fn get_champions() -> Vec<ChampionInfo> {
    let champs = vec![
        ("Aatrox", "Aatrox"), ("Ahri", "Ahri"), ("Akali", "Akali"),
        ("Alistar", "Alistar"), ("Amumu", "Amumu"), ("Anivia", "Anivia"),
        ("Annie", "Annie"), ("Ashe", "Ashe"), ("Azir", "Azir"),
        ("Blitzcrank", "Blitzcrank"), ("Brand", "Brand"), ("Braum", "Braum"),
        ("Caitlyn", "Caitlyn"), ("Cassiopeia", "Cassiopeia"), ("Chogath", "Cho'Gath"),
        ("Corki", "Corki"), ("Darius", "Darius"), ("Diana", "Diana"),
        ("DrMundo", "Dr. Mundo"), ("Draven", "Draven"), ("Elise", "Elise"),
        ("Evelynn", "Evelynn"), ("Ezreal", "Ezreal"), ("FiddleSticks", "Fiddlesticks"),
        ("Fiora", "Fiora"), ("Fizz", "Fizz"), ("Galio", "Galio"),
        ("Gangplank", "Gangplank"), ("Garen", "Garen"), ("Gnar", "Gnar"),
        ("Gragas", "Gragas"), ("Graves", "Graves"), ("Hecarim", "Hecarim"),
        ("Heimerdinger", "Heimerdinger"), ("Irelia", "Irelia"), ("Janna", "Janna"),
        ("JarvanIV", "Jarvan IV"), ("Jax", "Jax"), ("Jayce", "Jayce"),
        ("Jinx", "Jinx"), ("Kalista", "Kalista"), ("Karma", "Karma"),
        ("Karthus", "Karthus"), ("Kassadin", "Kassadin"), ("Katarina", "Katarina"),
        ("Kayle", "Kayle"), ("Kennen", "Kennen"), ("Khazix", "Kha'Zix"),
        ("KogMaw", "Kog'Maw"), ("Leblanc", "LeBlanc"), ("LeeSin", "Lee Sin"),
        ("Leona", "Leona"), ("Lissandra", "Lissandra"), ("Lucian", "Lucian"),
        ("Lulu", "Lulu"), ("Lux", "Lux"), ("Malphite", "Malphite"),
        ("Malzahar", "Malzahar"), ("Maokai", "Maokai"), ("MasterYi", "Master Yi"),
        ("MissFortune", "Miss Fortune"), ("MonkeyKing", "Wukong"),
        ("Mordekaiser", "Mordekaiser"), ("Morgana", "Morgana"), ("Nami", "Nami"),
        ("Nasus", "Nasus"), ("Nautilus", "Nautilus"), ("Nidalee", "Nidalee"),
        ("Nocturne", "Nocturne"), ("Nunu", "Nunu"), ("Olaf", "Olaf"),
        ("Orianna", "Orianna"), ("Pantheon", "Pantheon"), ("Poppy", "Poppy"),
        ("Quinn", "Quinn"), ("Rammus", "Rammus"), ("Renekton", "Renekton"),
        ("Rengar", "Rengar"), ("Riven", "Riven"), ("Rumble", "Rumble"),
        ("Ryze", "Ryze"), ("Sejuani", "Sejuani"), ("Shaco", "Shaco"),
        ("Shen", "Shen"), ("Shyvana", "Shyvana"), ("Singed", "Singed"),
        ("Sion", "Sion"), ("Sivir", "Sivir"), ("Skarner", "Skarner"),
        ("Sona", "Sona"), ("Soraka", "Soraka"), ("Swain", "Swain"),
        ("Syndra", "Syndra"), ("Talon", "Talon"), ("Taric", "Taric"),
        ("Teemo", "Teemo"), ("Thresh", "Thresh"), ("Tristana", "Tristana"),
        ("Trundle", "Trundle"), ("Tryndamere", "Tryndamere"),
        ("TwistedFate", "Twisted Fate"), ("Twitch", "Twitch"), ("Udyr", "Udyr"),
        ("Urgot", "Urgot"), ("Varus", "Varus"), ("Vayne", "Vayne"),
        ("Veigar", "Veigar"), ("Velkoz", "Vel'Koz"), ("Vi", "Vi"),
        ("Viktor", "Viktor"), ("Vladimir", "Vladimir"), ("Volibear", "Volibear"),
        ("Warwick", "Warwick"), ("Xerath", "Xerath"), ("XinZhao", "Xin Zhao"),
        ("Yasuo", "Yasuo"), ("Yorick", "Yorick"), ("Zac", "Zac"),
        ("Zed", "Zed"), ("Ziggs", "Ziggs"), ("Zilean", "Zilean"), ("Zyra", "Zyra"),
    ];
    champs.into_iter().map(|(name, display)| ChampionInfo {
        name: name.to_string(),
        display_name: display.to_string(),
    }).collect()
}

pub fn get_maps() -> Vec<MapInfo> {
    vec![
        MapInfo { id: 11, name: "Summoner's Rift".into(), players: "5v5".into() },
        MapInfo { id: 10, name: "Twisted Treeline".into(), players: "3v3".into() },
        MapInfo { id: 12, name: "Howling Abyss (ARAM)".into(), players: "5v5".into() },
        MapInfo { id: 8, name: "Crystal Scar".into(), players: "5v5".into() },
        MapInfo { id: 1, name: "Summoner's Rift (Old)".into(), players: "5v5".into() },
    ]
}

pub fn get_spells() -> Vec<SpellInfo> {
    let spells = vec![
        ("SummonerFlash", "Flash"),
        ("SummonerHeal", "Heal"),
        ("SummonerDot", "Ignite"),
        ("SummonerExhaust", "Exhaust"),
        ("SummonerTeleport", "Teleport"),
        ("SummonerSmite", "Smite"),
        ("SummonerBarrier", "Barrier"),
        ("SummonerBoost", "Cleanse"),
        ("SummonerHaste", "Ghost"),
        ("SummonerClairvoyance", "Clairvoyance"),
        ("SummonerMana", "Clarity"),
        ("SummonerRevive", "Revive"),
    ];
    spells.into_iter().map(|(name, display)| SpellInfo {
        name: name.to_string(),
        display_name: display.to_string(),
    }).collect()
}
