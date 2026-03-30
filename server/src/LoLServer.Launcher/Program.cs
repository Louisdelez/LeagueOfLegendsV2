using System;
using System.Diagnostics;
using System.IO;
using LoLServer.Core.Config;

namespace LoLServer.Launcher;

/// <summary>
/// Launches "League of Legends.exe" pointed at our local server.
///
/// Launch command format:
/// "League of Legends.exe" "8394" "LoLLauncher.exe" "" "SERVER_IP PORT BLOWFISH_KEY PLAYER_ID"
/// </summary>
class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine(@"
  ╔═══════════════════════════════════════════╗
  ║     LoL Client Launcher v0.1.0            ║
  ║     Connects to local private server      ║
  ╚═══════════════════════════════════════════╝
");

        // Load config
        var configPath = args.Length > 0 ? args[0] : FindConfigPath();
        if (configPath == null || !File.Exists(configPath))
        {
            Console.WriteLine("Usage: LoLServer.Launcher [path-to-gameconfig.json]");
            Console.WriteLine("Config not found. Run LoLServer.Console first to generate one.");
            return;
        }

        var config = GameConfig.LoadFromFile(configPath);
        Console.WriteLine($"Config loaded from {configPath}");

        // Validate client path
        var gameExe = Path.Combine(config.ClientPath, "League of Legends.exe");
        if (!File.Exists(gameExe))
        {
            Console.WriteLine($"[ERROR] Game executable not found at: {gameExe}");
            Console.WriteLine($"Set 'clientPath' in {configPath} to the Game/ directory");
            Console.WriteLine("Example: /media/louisdelez/VM/LeagueOfLegendsV2/client/Game");
            return;
        }

        Console.WriteLine($"Game exe: {gameExe}");
        Console.WriteLine($"Server: 127.0.0.1:{config.ServerPort}");

        // Launch each player
        for (int i = 0; i < config.Players.Count; i++)
        {
            var player = config.Players[i];
            var key = player.BlowfishKey ?? config.BlowfishKey;

            LaunchClient(gameExe, config.ClientPath, config.ServerPort, key, player.PlayerId, i);
        }

        Console.WriteLine();
        Console.WriteLine("Client(s) launched. Press Enter to exit launcher.");
        Console.ReadLine();
    }

    static void LaunchClient(string gameExe, string workDir, int port, string blowfishKey, ulong playerId, int index)
    {
        // Format: "League of Legends.exe" "8394" "LoLLauncher.exe" "" "127.0.0.1 PORT KEY PLAYERID"
        var connectionString = $"127.0.0.1 {port} {blowfishKey} {playerId}";

        var arguments = $"\"8394\" \"LoLLauncher.exe\" \"\" \"{connectionString}\"";

        Console.WriteLine($"[Player {index}] Launching with:");
        Console.WriteLine($"  Command: \"{gameExe}\" {arguments}");
        Console.WriteLine($"  WorkDir: {workDir}");
        Console.WriteLine($"  Key: {blowfishKey}");
        Console.WriteLine($"  PlayerID: {playerId}");

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = gameExe,
                Arguments = arguments,
                WorkingDirectory = workDir,
                UseShellExecute = false,
                RedirectStandardOutput = false,
                RedirectStandardError = false
            };

            var process = Process.Start(psi);
            if (process != null)
            {
                Console.WriteLine($"  [OK] Client launched (PID: {process.Id})");
            }
            else
            {
                Console.WriteLine($"  [ERROR] Failed to start client process");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  [ERROR] {ex.Message}");

            // On Linux, suggest Wine
            if (Environment.OSVersion.Platform == PlatformID.Unix)
            {
                Console.WriteLine("  [TIP] On Linux, you need Wine to run League of Legends.exe:");
                Console.WriteLine($"  wine \"{gameExe}\" {arguments}");

                // Try with Wine
                Console.Write("  Try with Wine? (y/n): ");
                if (Console.ReadLine()?.ToLower() == "y")
                {
                    LaunchWithWine(gameExe, arguments, workDir);
                }
            }
        }
    }

    static void LaunchWithWine(string gameExe, string arguments, string workDir)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "wine",
                Arguments = $"\"{gameExe}\" {arguments}",
                WorkingDirectory = workDir,
                UseShellExecute = false
            };

            var process = Process.Start(psi);
            if (process != null)
            {
                Console.WriteLine($"  [OK] Client launched via Wine (PID: {process.Id})");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  [ERROR] Wine launch failed: {ex.Message}");
            Console.WriteLine("  Install Wine: sudo apt install wine64");
        }
    }

    static string? FindConfigPath()
    {
        // Look in common locations
        var paths = new[]
        {
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "gameconfig.json"),
            Path.Combine(Directory.GetCurrentDirectory(), "gameconfig.json"),
            Path.Combine(Directory.GetCurrentDirectory(), "server", "src", "LoLServer.Console", "bin", "Debug", "net8.0", "gameconfig.json"),
        };

        foreach (var path in paths)
        {
            if (File.Exists(path))
                return path;
        }

        return paths[0]; // Return default even if not found
    }
}
