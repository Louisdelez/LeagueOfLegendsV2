using System;
using System.IO;
using LoLServer.Core.Config;
using LoLServer.Core.Lobby;
using LoLServer.Core.Network;

namespace LoLServer.Console;

class Program
{
    static void Main(string[] args)
    {
        System.Console.WriteLine(@"
  ╔═══════════════════════════════════════════╗
  ║     LoL Private Server v0.1.0             ║
  ║     Compatible with modern LoL client     ║
  ╚═══════════════════════════════════════════╝
");

        // Load or create config
        var configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "gameconfig.json");
        GameConfig config;

        if (File.Exists(configPath))
        {
            System.Console.WriteLine($"Loading config from {configPath}");
            config = GameConfig.LoadFromFile(configPath);
        }
        else
        {
            System.Console.WriteLine($"No config found. Creating default config at {configPath}");
            config = new GameConfig();

            // Try to auto-detect client path
            var possiblePaths = new[]
            {
                Path.Combine(Directory.GetCurrentDirectory(), "..", "..", "..", "..", "client", "Game"),
                @"C:\Riot Games\League of Legends\Game",
                @"D:\Riot Games\League of Legends\Game",
                @"D:\Programm\Riot Games\League of Legends\Game",
            };

            foreach (var path in possiblePaths)
            {
                if (Directory.Exists(path))
                {
                    config.ClientPath = Path.GetFullPath(path);
                    System.Console.WriteLine($"Auto-detected client path: {config.ClientPath}");
                    break;
                }
            }

            config.SaveToFile(configPath);
            System.Console.WriteLine($"Config saved. Edit {configPath} to customize.");
        }

        // Parse command-line args
        bool rawCapture = false;
        foreach (var arg in args)
        {
            if (arg == "--raw" || arg == "-r")
                rawCapture = true;
            if (arg.StartsWith("--port="))
                config.ServerPort = int.Parse(arg.Split('=')[1]);
            if (arg.StartsWith("--client="))
                config.ClientPath = arg.Split('=', 2)[1];
        }

        System.Console.WriteLine($"Server port: {config.ServerPort}");
        System.Console.WriteLine($"Client path: {config.ClientPath}");
        System.Console.WriteLine($"Game version: {config.GameVersion}");
        System.Console.WriteLine($"Map: {config.MapId}");
        System.Console.WriteLine($"Raw capture: {rawCapture}");
        System.Console.WriteLine();

        // Log to file
        var logDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
        Directory.CreateDirectory(logDir);
        var logFile = Path.Combine(logDir, $"server_{DateTime.Now:yyyyMMdd_HHmmss}.log");
        var logWriter = new StreamWriter(logFile, append: true) { AutoFlush = true };

        // Start server
        using var server = new PacketServer(config.ServerPort, config);

        server.OnLog += msg => logWriter.WriteLine(msg);
        server.OnRawPacket += (data, channel, desc) =>
        {
            // Save raw packets for analysis
            var packetDir = Path.Combine(logDir, "packets");
            Directory.CreateDirectory(packetDir);
            var filename = $"{DateTime.Now:HHmmss_fff}_ch{channel}_{desc.Replace(" ", "_")}.bin";
            File.WriteAllBytes(Path.Combine(packetDir, filename), data);
        };

        if (rawCapture)
            server.EnableRawCapture();

        // Start lobby web server
        LobbyServer? lobby = null;
        try
        {
            lobby = new LobbyServer(8080);
            lobby.OnGameStart += lobbyConfig =>
            {
                System.Console.WriteLine($"[LOBBY] Game config received! {lobbyConfig.Players.Count} players");
                // Update game config from lobby
                config.Players = lobbyConfig.Players;
                config.MapId = lobbyConfig.MapId;
                config.GameMode = lobbyConfig.GameMode;
                config.SaveToFile(configPath);
            };
            lobby.Start();
        }
        catch (Exception ex)
        {
            System.Console.WriteLine($"[WARN] Lobby server failed (need sudo for port 8080?): {ex.Message}");
            System.Console.WriteLine("[WARN] Try: sudo setcap 'cap_net_bind_service=+ep' $(which dotnet)");
        }

        System.Console.WriteLine($"Log file: {logFile}");
        System.Console.WriteLine("Press Ctrl+C to stop the server.");
        System.Console.WriteLine();

        // Handle Ctrl+C
        System.Console.CancelKeyPress += (s, e) =>
        {
            e.Cancel = true;
            server.Stop();
            lobby?.Stop();
            System.Console.WriteLine("\nServer stopped.");
        };

        try
        {
            server.Start();
        }
        catch (Exception ex)
        {
            System.Console.WriteLine($"[FATAL] {ex.Message}");
            System.Console.WriteLine(ex.StackTrace);
        }
        finally
        {
            logWriter.Close();
        }
    }
}
