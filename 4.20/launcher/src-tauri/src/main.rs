mod config;
mod data;
mod launcher;

use config::GameConfig;
use data::{ChampionInfo, MapInfo, SpellInfo};
use launcher::Paths;
use std::thread;

const BASE_PATH: &str = "D:/LeagueOfLegendsV2/4.20";

#[tauri::command]
fn get_champions() -> Vec<ChampionInfo> {
    data::get_champions()
}

#[tauri::command]
fn get_maps() -> Vec<MapInfo> {
    data::get_maps()
}

#[tauri::command]
fn get_summoner_spells() -> Vec<SpellInfo> {
    data::get_spells()
}

#[tauri::command]
fn launch_game(
    player_name: String,
    champion: String,
    map_id: u32,
    summoner1: String,
    summoner2: String,
    skin: u32,
    minions_enabled: bool,
    cooldowns_enabled: bool,
    mana_enabled: bool,
) -> Result<String, String> {
    let paths = Paths::detect(BASE_PATH);

    let game_config = GameConfig {
        player_name,
        champion,
        map_id,
        summoner1,
        summoner2,
        skin,
        minions_enabled,
        cooldowns_enabled,
        mana_enabled,
    };

    let settings_path = paths.settings_dir.join("GameInfo.json");
    config::generate_and_write(&game_config, &settings_path)?;

    thread::spawn(move || {
        if let Err(e) = launcher::launch_server(&paths) {
            eprintln!("Server error: {}", e);
            return;
        }
        if let Err(e) = launcher::launch_client(&paths) {
            eprintln!("Client error: {}", e);
        }
    });

    Ok("Game launching...".into())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_champions,
            get_maps,
            get_summoner_spells,
            launch_game,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
