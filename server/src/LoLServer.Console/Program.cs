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

        // Parse command-line args (values first, then modes)
        bool rawCapture = false;
        bool testMode = false;
        bool rawUdpMode = false;
        string? runMode = null;
        foreach (var arg in args)
        {
            if (arg == "--raw" || arg == "-r") rawCapture = true;
            else if (arg == "--test" || arg == "-t") testMode = true;
            else if (arg == "--rawudp" || arg == "--modern") rawUdpMode = true;
            else if (arg == "--dtls") runMode = "dtls";
            else if (arg == "--capture" || arg == "-c") runMode = "capture";
            else if (arg == "--analyze" || arg == "-a") runMode = "analyze";
            else if (arg == "--custom" || arg == "-u") runMode = "custom";
            else if (arg == "--decrypt-test") runMode = "decrypt";
            else if (arg == "--key-test") runMode = "keytest";
            else if (arg == "--cbc-test") runMode = "cbc";
            else if (arg == "--replay-test") runMode = "replay";
            else if (arg == "--decode") runMode = "decode";
            else if (arg == "--riot-decode") runMode = "riot-decode";
            else if (arg == "--transcrypt") runMode = "transcrypt";
            else if (arg == "--crypto") runMode = "crypto";
            else if (arg == "--crypto-test") runMode = "crypto-test";
            else if (arg == "--lenet-decode") runMode = "lenet-decode";
            else if (arg == "--crack") runMode = "crack";
            else if (arg.StartsWith("--port=")) config.ServerPort = int.Parse(arg.Split('=')[1]);
            else if (arg.StartsWith("--client=")) config.ClientPath = arg.Split('=', 2)[1];
        }

        // Handle tool modes (after all args are parsed so --port= works)
        switch (runMode)
        {
            case "capture": RawCapture.Run(config.ServerPort); return;
            case "analyze": ProtocolAnalyzer.Run(); return;
            case "custom": CustomUdpServer.Run(config.ServerPort, config.BlowfishKey); return;
            case "decrypt": DecryptTest.Run(config.BlowfishKey); return;
            case "keytest": KeyDerivationTest.Run(config.BlowfishKey); return;
            case "cbc": CbcDecryptTest.Run(config.BlowfishKey); return;
            case "replay": ReplayTest.Run(config.ServerPort); return;
            case "decode": PacketDecoder.Run(); return;
            case "riot-decode": RiotProtocolDecoder.Run(); return;
            case "transcrypt": TranscryptTest.Run(); return;
            case "crypto": CryptoAnalysis.Run(); return;
            case "crypto-test": CryptoModeTest.Run(); return;
            case "lenet-decode": LENetDecoder.Run(); return;
            case "crack": PacketCrack.Run(); return;
        }

        // Test mode: run simulated client against a running server
        if (testMode)
        {
            TestClient.Run("127.0.0.1", config.ServerPort);
            return;
        }

        System.Console.WriteLine($"Server port: {config.ServerPort}");
        System.Console.WriteLine($"Client path: {config.ClientPath}");
        System.Console.WriteLine($"Game version: {config.GameVersion}");
        System.Console.WriteLine($"Map: {config.MapId}");
        System.Console.WriteLine($"Mode: {(rawUdpMode ? "Raw UDP (modern client)" : "LENet (auto-detect)")}");
        System.Console.WriteLine($"Raw capture: {rawCapture}");
        System.Console.WriteLine();

        // Log to file
        var logDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
        Directory.CreateDirectory(logDir);
        var logFile = Path.Combine(logDir, $"server_{DateTime.Now:yyyyMMdd_HHmmss}.log");
        var logWriter = new StreamWriter(logFile, append: true) { AutoFlush = true };

        // Start lobby web server
        LobbyServer? lobby = null;
        try
        {
            lobby = new LobbyServer(8888);
            lobby.OnGameStart += lobbyConfig =>
            {
                System.Console.WriteLine($"[LOBBY] Game config received! {lobbyConfig.Players.Count} players");
                config.Players = lobbyConfig.Players;
                config.MapId = lobbyConfig.MapId;
                config.GameMode = lobbyConfig.GameMode;
                config.SaveToFile(configPath);
            };
            lobby.Start();
        }
        catch (Exception ex)
        {
            System.Console.WriteLine($"[WARN] Lobby server failed: {ex.Message}");
        }

        // Start Fake LCU (WSS) — needed for modern client
        var fakeLcu = new LoLServer.Core.Network.FakeLCU();
        fakeLcu.Start();
        System.Console.WriteLine();

        System.Console.WriteLine($"Log file: {logFile}");
        System.Console.WriteLine("Press Ctrl+C to stop the server.");
        System.Console.WriteLine();

        if (runMode == "dtls" || rawUdpMode)
        {
            // === DTLS/Raw UDP mode for modern LoL client ===
            bool useDtls = (runMode == "dtls");

            // Try DTLS first, fall back to raw UDP
            if (useDtls)
            {
                System.Console.WriteLine("[MODE] DTLS - BouncyCastle DTLS server");
                using var dtlsServer = new DtlsGameServer(config.ServerPort, config);
                dtlsServer.OnLog += msg => logWriter.WriteLine(msg);

                System.Console.CancelKeyPress += (s, e) =>
                {
                    e.Cancel = true;
                    dtlsServer.Stop();
                    fakeLcu.Stop();
                    lobby?.Stop();
                };

                try { dtlsServer.Start(); }
                catch (Exception ex)
                {
                    System.Console.WriteLine($"[FATAL] {ex.Message}");
                    System.Console.WriteLine(ex.StackTrace);
                }
                logWriter.Close();
                return;
            }

            using var rawServer = new RawGameServer(config.ServerPort, config);
            rawServer.OnLog += msg => logWriter.WriteLine(msg);

            System.Console.CancelKeyPress += (s, e) =>
            {
                e.Cancel = true;
                rawServer.Stop();
                fakeLcu.Stop();
                lobby?.Stop();
                System.Console.WriteLine("\nServer stopped.");
            };

            try
            {
                rawServer.Start();
            }
            catch (Exception ex)
            {
                System.Console.WriteLine($"[FATAL] {ex.Message}");
                System.Console.WriteLine(ex.StackTrace);
            }
        }
        else
        {
            // === LENet mode: standard ENet with auto-detect ===
            using var server = new PacketServer(config.ServerPort, config);
            server.OnLog += msg => logWriter.WriteLine(msg);
            server.OnRawPacket += (data, channel, desc) =>
            {
                var packetDir = Path.Combine(logDir, "packets");
                Directory.CreateDirectory(packetDir);
                var filename = $"{DateTime.Now:HHmmss_fff}_ch{channel}_{desc.Replace(" ", "_")}.bin";
                File.WriteAllBytes(Path.Combine(packetDir, filename), data);
            };

            if (rawCapture)
                server.EnableRawCapture();

            System.Console.CancelKeyPress += (s, e) =>
            {
                e.Cancel = true;
                server.Stop();
                fakeLcu.Stop();
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
        }

        logWriter.Close();
    }
}
