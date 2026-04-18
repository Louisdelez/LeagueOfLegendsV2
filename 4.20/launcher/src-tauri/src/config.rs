use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Deserialize)]
pub struct GameConfig {
    pub player_name: String,
    pub champion: String,
    pub map_id: u32,
    pub summoner1: String,
    pub summoner2: String,
    pub skin: u32,
    pub minions_enabled: bool,
    pub cooldowns_enabled: bool,
    pub mana_enabled: bool,
}

#[derive(Serialize)]
struct GameInfoJson {
    players: Vec<PlayerConfig>,
    game: GameSettings,
    #[serde(rename = "gameInfo")]
    game_info: GameInfoSettings,
    #[serde(rename = "forcedStart")]
    forced_start: u32,
}

#[derive(Serialize)]
struct PlayerConfig {
    #[serde(rename = "playerId")]
    player_id: u32,
    #[serde(rename = "blowfishKey")]
    blowfish_key: String,
    rank: String,
    name: String,
    champion: String,
    team: String,
    skin: u32,
    summoner1: String,
    summoner2: String,
    ribbon: u32,
    icon: u32,
    runes: HashMap<String, u32>,
    talents: HashMap<String, u32>,
}

#[derive(Serialize)]
struct GameSettings {
    map: u32,
    #[serde(rename = "gameMode")]
    game_mode: String,
    #[serde(rename = "dataPackage")]
    data_package: String,
}

#[derive(Serialize)]
struct GameInfoSettings {
    #[serde(rename = "MANACOSTS_ENABLED")]
    manacosts_enabled: bool,
    #[serde(rename = "COOLDOWNS_ENABLED")]
    cooldowns_enabled: bool,
    #[serde(rename = "CHEATS_ENABLED")]
    cheats_enabled: bool,
    #[serde(rename = "MINION_SPAWNS_ENABLED")]
    minion_spawns_enabled: bool,
    #[serde(rename = "CONTENT_PATH")]
    content_path: String,
    #[serde(rename = "IS_DAMAGE_TEXT_GLOBAL")]
    is_damage_text_global: bool,
}

fn default_runes() -> HashMap<String, u32> {
    let mut runes = HashMap::new();
    for i in 1..=9 { runes.insert(i.to_string(), 5245); }   // AD Marks
    for i in 10..=18 { runes.insert(i.to_string(), 5317); }  // Armor Seals
    for i in 19..=27 { runes.insert(i.to_string(), 5289); }  // MR Glyphs
    for i in 28..=30 { runes.insert(i.to_string(), 5335); }  // AS Quints
    runes
}

fn default_talents() -> HashMap<String, u32> {
    let mut t = HashMap::new();
    // 21/9/0 AD Carry page
    t.insert("4111".into(), 1); t.insert("4112".into(), 3);
    t.insert("4114".into(), 1); t.insert("4122".into(), 3);
    t.insert("4124".into(), 1); t.insert("4132".into(), 1);
    t.insert("4134".into(), 3); t.insert("4142".into(), 3);
    t.insert("4151".into(), 1); t.insert("4152".into(), 1);
    t.insert("4162".into(), 1);
    t.insert("4211".into(), 2); t.insert("4212".into(), 2);
    t.insert("4213".into(), 2); t.insert("4221".into(), 1);
    t.insert("4222".into(), 1); t.insert("4232".into(), 1);
    t
}

pub fn generate_and_write(config: &GameConfig, settings_path: &Path) -> Result<(), String> {
    let game_mode = match config.map_id {
        12 => "ARAM",
        8 => "ODIN",
        _ => "CLASSIC",
    };

    let game_info = GameInfoJson {
        players: vec![PlayerConfig {
            player_id: 1,
            blowfish_key: "17BLOhi6KZsTtldTsizvHg==".into(),
            rank: "DIAMOND".into(),
            name: config.player_name.clone(),
            champion: config.champion.clone(),
            team: "BLUE".into(),
            skin: config.skin,
            summoner1: config.summoner1.clone(),
            summoner2: config.summoner2.clone(),
            ribbon: 2,
            icon: 0,
            runes: default_runes(),
            talents: default_talents(),
        }],
        game: GameSettings {
            map: config.map_id,
            game_mode: game_mode.into(),
            data_package: "LeagueSandbox-Scripts".into(),
        },
        game_info: GameInfoSettings {
            manacosts_enabled: config.mana_enabled,
            cooldowns_enabled: config.cooldowns_enabled,
            cheats_enabled: true,
            minion_spawns_enabled: config.minions_enabled,
            content_path: "../../../../../Content".into(),
            is_damage_text_global: false,
        },
        forced_start: 10,
    };

    let json = serde_json::to_string_pretty(&game_info)
        .map_err(|e| format!("JSON error: {}", e))?;
    fs::write(settings_path, &json)
        .map_err(|e| format!("Write error: {}", e))?;
    Ok(())
}
