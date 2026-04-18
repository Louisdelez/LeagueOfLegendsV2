use std::process::Command;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

pub struct Paths {
    pub server_dll: PathBuf,
    pub server_dir: PathBuf,
    pub client_exe: PathBuf,
    pub client_dir: PathBuf,
    pub settings_dir: PathBuf,
}

impl Paths {
    pub fn detect(base: &str) -> Self {
        let base = PathBuf::from(base);
        Paths {
            server_dll: base.join("GameServer/GameServerConsole/bin/Debug/net6.0/GameServerConsole.dll"),
            server_dir: base.join("GameServer/GameServerConsole/bin/Debug/net6.0"),
            client_exe: base.join("Client/League of Legends_UNPACKED/League-of-Legends-4-20/RADS/solutions/lol_game_client_sln/releases/0.0.1.68/deploy/League of Legends.exe"),
            client_dir: base.join("Client/League of Legends_UNPACKED/League-of-Legends-4-20/RADS/solutions/lol_game_client_sln/releases/0.0.1.68/deploy"),
            settings_dir: base.join("GameServer/GameServerConsole/bin/Debug/net6.0/Settings"),
        }
    }
}

pub fn launch_server(paths: &Paths) -> Result<(), String> {
    if !paths.server_dll.exists() {
        return Err(format!("Server not found: {:?}", paths.server_dll));
    }

    Command::new("dotnet")
        .arg(paths.server_dll.to_str().unwrap())
        .arg("--port")
        .arg("5119")
        .current_dir(&paths.server_dir)
        .spawn()
        .map_err(|e| format!("Failed to start server: {}", e))?;

    Ok(())
}

pub fn launch_client(paths: &Paths) -> Result<(), String> {
    if !paths.client_exe.exists() {
        return Err(format!("Client not found: {:?}", paths.client_exe));
    }

    thread::sleep(Duration::from_secs(4));

    Command::new(paths.client_exe.to_str().unwrap())
        .args([
            "8394",
            "LoLLauncher.exe",
            "",
            "127.0.0.1 5119 17BLOhi6KZsTtldTsizvHg== 1",
        ])
        .current_dir(&paths.client_dir)
        .spawn()
        .map_err(|e| format!("Failed to start client: {}", e))?;

    Ok(())
}
