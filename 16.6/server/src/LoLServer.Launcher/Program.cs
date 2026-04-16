using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using LoLServer.Core.Config;

namespace LoLServer.Launcher;

/// <summary>
/// Launches the REAL "League of Legends.exe" pointed at our private server.
///
/// Based on real client logs (patch 16.6), the launch command is:
///   "League of Legends.exe" "SERVER_IP PORT BLOWFISH_KEY PLAYER_ID"
///     -Product=LoL -PlayerID=PLAYER_ID -GameID=1
///     -GameBaseDir=PATH -Region=EUW -PlatformID=EUW1 -Locale=fr_FR
///     -SkipBuild -EnableCrashpad=false -RiotClientPort=PORT -RiotClientAuthToken=TOKEN
///
/// The client also connects to RiotClientPort (HTTP) for LCU communication.
/// We run a fake RiotClient HTTP stub so the client doesn't crash.
/// </summary>
class Program
{
    private const string AuthToken = "PrivateServerToken123";
    private static int _riotClientPort = 0;

    static void Main(string[] args)
    {
        System.Console.WriteLine(@"
  ╔═══════════════════════════════════════════════╗
  ║     LoL Private Server - Client Launcher      ║
  ║     Launches the REAL LoL client               ║
  ╚═══════════════════════════════════════════════╝
");

        // Load config
        var configPath = args.Length > 0 && !args[0].StartsWith("-") ? args[0] : FindConfigPath();
        GameConfig config;

        if (configPath != null && File.Exists(configPath))
        {
            config = GameConfig.LoadFromFile(configPath);
            System.Console.WriteLine($"Config loaded from {configPath}");
        }
        else
        {
            config = new GameConfig();
            System.Console.WriteLine("Using default config (no gameconfig.json found)");
        }

        // Find client
        var gamePath = FindGamePath(config);
        if (gamePath == null)
        {
            System.Console.WriteLine("[ERROR] Cannot find League of Legends installation!");
            System.Console.WriteLine("Searched in:");
            System.Console.WriteLine("  - D:\\Programm\\Riot Games\\League of Legends\\Game\\");
            System.Console.WriteLine("  - D:\\Riot Games\\League of Legends\\Game\\");
            System.Console.WriteLine("  - C:\\Riot Games\\League of Legends\\Game\\");
            System.Console.WriteLine();
            System.Console.WriteLine("Set 'clientPath' in gameconfig.json to your Game\\ folder.");
            return;
        }

        // Use patched exe to avoid Vanguard kernel driver blocking us
        var gameExe = Path.Combine(gamePath, "LoLPrivate.exe");
        var originalExe = Path.Combine(gamePath, "League of Legends.exe");

        if (!File.Exists(gameExe))
        {
            if (!File.Exists(originalExe))
            {
                System.Console.WriteLine($"[ERROR] No League of Legends.exe found in {gamePath}");
                return;
            }

            System.Console.WriteLine("[SETUP] Creating patched LoLPrivate.exe...");
            File.Copy(originalExe, gameExe, overwrite: true);
            PatchExeForPrivateServer(gameExe);
            System.Console.WriteLine("[SETUP] Done! Patched exe ready.");
        }
        var baseDir = Path.GetFullPath(Path.Combine(gamePath, ".."));

        System.Console.WriteLine($"Client: {gameExe}");
        System.Console.WriteLine($"BaseDir: {baseDir}");
        System.Console.WriteLine($"Server: 127.0.0.1:{config.ServerPort}");
        System.Console.WriteLine($"Players: {config.Players.Count}");
        System.Console.WriteLine();

        // Try to use the Console server's FakeLCU (it persists, ours would die when Launcher exits)
        _riotClientPort = LoLServer.Core.Network.FakeLCU.ReadPortFromFile();
        if (_riotClientPort <= 0)
        {
            // Console server not running — start our own FakeLCU
            System.Console.WriteLine("[LCU] No running FakeLCU found, starting our own...");
            var fakeLcu = new LoLServer.Core.Network.FakeLCU();
            fakeLcu.Start();
            _riotClientPort = fakeLcu.Port;
        }
        System.Console.WriteLine();

        // Launch client for first player (or specified player)
        int playerIndex = 0;
        foreach (var arg in args)
        {
            if (arg.StartsWith("--player="))
                playerIndex = int.Parse(arg.Split('=')[1]);
        }

        if (playerIndex >= config.Players.Count)
            playerIndex = 0;

        var player = config.Players[playerIndex];
        var key = player.BlowfishKey ?? config.BlowfishKey;

        LaunchClient(gameExe, baseDir, gamePath, config, player, key, playerIndex);

        System.Console.WriteLine();
        System.Console.WriteLine("Client launched! Check the game server console for connection.");
        System.Console.WriteLine("Press Enter to kill client and exit.");
        System.Console.ReadLine();
    }

    static void LaunchClient(string gameExe, string baseDir, string gamePath,
        GameConfig config, PlayerConfig player, string blowfishKey, int index)
    {
        // Connection string: "IP PORT KEY PLAYERID" (first positional arg)
        var connectionString = $"127.0.0.1 {config.ServerPort} {blowfishKey} {player.PlayerId}";

        // Build the full argument list matching real client launch
        var sb = new StringBuilder();
        sb.Append($"\"{connectionString}\"");
        sb.Append($" \"-Product=LoL\"");
        sb.Append($" \"-PlayerID={player.PlayerId}\"");
        sb.Append($" \"-GameID=1\"");
        sb.Append($" \"-PlayerNameMode=ALIAS\"");
        // LNPBlob = base64([4B magic 37AA0014][4B sessionID])
        // The client uses this to know the protocol magic and session ID
        var sessionIdBytes = BitConverter.GetBytes((uint)0xDEADBEEF);
        var lnpBlob = new byte[] { 0x37, 0xAA, 0x00, 0x14 };
        var fullBlob = new byte[8];
        Array.Copy(lnpBlob, 0, fullBlob, 0, 4);
        Array.Copy(sessionIdBytes, 0, fullBlob, 4, 4);
        var lnpBase64 = Convert.ToBase64String(fullBlob);
        sb.Append($" \"-LNPBlob={lnpBase64}\"");
        sb.Append($" \"-GameBaseDir={baseDir}\"");
        sb.Append($" \"-Region=EUW\"");
        sb.Append($" \"-PlatformID=EUW1\"");
        sb.Append($" \"-Locale=fr_FR\"");
        sb.Append($" \"-SkipBuild\"");
        sb.Append($" \"-EnableCrashpad=false\"");
        sb.Append($" \"-RiotClientPort={_riotClientPort}\"");
        sb.Append($" \"-RiotClientAuthToken={AuthToken}\"");

        var arguments = sb.ToString();

        System.Console.WriteLine($"[Player {index}] {player.Name} - {player.Champion}");
        System.Console.WriteLine($"  Team: {player.Team}");
        System.Console.WriteLine($"  PlayerID: {player.PlayerId}");
        System.Console.WriteLine($"  BlowfishKey: {blowfishKey}");
        System.Console.WriteLine();
        System.Console.WriteLine($"  Command:");
        System.Console.WriteLine($"    \"{gameExe}\" {arguments}");
        System.Console.WriteLine();

        try
        {
            // The LoL client uses OpenSSL which reads SSL_CERT_FILE
            // for trusted CA certificates. Point it to our CA ROOT cert (not server cert!)
            var certPath = Path.GetFullPath(Path.Combine(FindRepoRoot(), "myCA.crt"));
            if (!File.Exists(certPath))
                certPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "myCA.crt");
            if (!File.Exists(certPath))
                certPath = Path.GetFullPath(Path.Combine(
                    AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..",
                    "LoLServer.Console", "bin", "Debug", "net8.0", "myCA.crt"));

            // Set SSL_CERT_FILE for the game process — OpenSSL reads this as trust store
            if (File.Exists(certPath))
            {
                // Set for both user AND process (process env is inherited by child)
                Environment.SetEnvironmentVariable("SSL_CERT_FILE", certPath, EnvironmentVariableTarget.User);
                Environment.SetEnvironmentVariable("SSL_CERT_FILE", certPath, EnvironmentVariableTarget.Process);
                System.Console.WriteLine($"  SSL_CERT_FILE={certPath} (CA root cert)");

                // Also copy CA cert into game dir for version.dll to use
                var gameCACert = Path.Combine(gamePath, "myCA.crt");
                try { File.Copy(certPath, gameCACert, overwrite: true); } catch { }
            }
            else
            {
                System.Console.WriteLine($"  [WARN] FakeLCU cert not found at {certPath}");
            }

            var psi = new ProcessStartInfo
            {
                FileName = gameExe,
                Arguments = arguments,
                WorkingDirectory = gamePath,
                UseShellExecute = false, // false = inherit env vars (SSL_CERT_FILE!)
            };

            // Ensure SSL_CERT_FILE is in the child process environment
            if (File.Exists(certPath))
            {
                psi.Environment["SSL_CERT_FILE"] = certPath;
                System.Console.WriteLine($"  SSL_CERT_FILE injected into process env");
            }

            var process = Process.Start(psi);
            if (process != null)
            {
                System.Console.WriteLine($"  [OK] Client launched (PID: {process.Id})");

                // Monitor the process
                var monitor = new Thread(() =>
                {
                    process.WaitForExit();
                    System.Console.WriteLine($"  [EXIT] Client exited with code {process.ExitCode}");

                    // Check for crash logs
                    var logDir = Path.Combine(baseDir, "Logs", "GameLogs");
                    if (Directory.Exists(logDir))
                    {
                        var latestLog = GetLatestDirectory(logDir);
                        if (latestLog != null)
                        {
                            var r3dlog = Path.Combine(latestLog, Path.GetFileName(latestLog) + "_r3dlog.txt");
                            if (File.Exists(r3dlog))
                            {
                                System.Console.WriteLine($"  [LOG] Game log: {r3dlog}");
                                // Show last 20 lines
                                var lines = File.ReadAllLines(r3dlog);
                                int start = Math.Max(0, lines.Length - 20);
                                System.Console.WriteLine("  --- Last 20 lines of game log ---");
                                for (int i = start; i < lines.Length; i++)
                                    System.Console.WriteLine($"  {lines[i]}");
                            }
                        }
                    }
                })
                { IsBackground = true };
                monitor.Start();
            }
            else
            {
                System.Console.WriteLine($"  [ERROR] Failed to start client process");
            }
        }
        catch (Exception ex)
        {
            System.Console.WriteLine($"  [ERROR] {ex.Message}");
        }
    }

    /// <summary>
    /// Start a fake RiotClient HTTP server.
    /// The LoL client connects to this for LCU (League Client Update) communication.
    /// Without it, the client may crash or hang.
    /// </summary>
    static int StartFakeRiotClient()
    {
        // Find a free port
        var listener = new TcpPortFinder();
        int port = listener.FindFreePort();

        var httpListener = new HttpListener();
        httpListener.Prefixes.Add($"http://localhost:{port}/");
        httpListener.Start();

        var thread = new Thread(() =>
        {
            while (httpListener.IsListening)
            {
                try
                {
                    var ctx = httpListener.GetContext();
                    HandleLcuRequest(ctx);
                }
                catch (HttpListenerException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    System.Console.WriteLine($"  [LCU] Error: {ex.Message}");
                }
            }
        })
        { IsBackground = true, Name = "FakeRiotClient" };
        thread.Start();

        return port;
    }

    /// <summary>
    /// Handle LCU HTTP requests from the game client.
    /// The client makes various API calls - we respond with minimal valid JSON.
    /// </summary>
    static void HandleLcuRequest(HttpListenerContext ctx)
    {
        var path = ctx.Request.Url?.AbsolutePath ?? "/";
        var method = ctx.Request.HttpMethod;

        System.Console.WriteLine($"  [LCU] {method} {path}");

        string responseJson;

        // Route common LCU endpoints
        if (path.Contains("/riotclient/auth-token"))
        {
            responseJson = $"\"{AuthToken}\"";
        }
        else if (path.Contains("/riotclient/region-locale"))
        {
            responseJson = "{\"locale\":\"fr_FR\",\"region\":\"EUW\",\"webLanguage\":\"fr\",\"webRegion\":\"euw\"}";
        }
        else if (path.Contains("/chat/v1/session"))
        {
            responseJson = "{\"loaded\":true,\"state\":\"connected\"}";
        }
        else if (path.Contains("/lol-chat/v1"))
        {
            responseJson = "{\"state\":\"connected\"}";
        }
        else if (path.Contains("/performance/v1"))
        {
            responseJson = "{}";
        }
        else if (path.Contains("/process-control/v1"))
        {
            responseJson = "{\"status\":\"ok\"}";
        }
        else if (path.Contains("/system/v1"))
        {
            responseJson = "{\"initialized\":true}";
        }
        else if (path.Contains("/player-notifications"))
        {
            responseJson = "[]";
        }
        else if (path.Contains("/lol-game-client-chat"))
        {
            responseJson = "{\"state\":\"connected\"}";
        }
        else if (path.Contains("/voice-chat"))
        {
            responseJson = "{\"connected\":false}";
        }
        else if (path.Contains("/muted-players"))
        {
            responseJson = "[]";
        }
        else
        {
            // Default: return empty OK
            responseJson = "{}";
        }

        var responseBytes = Encoding.UTF8.GetBytes(responseJson);
        ctx.Response.StatusCode = 200;
        ctx.Response.ContentType = "application/json";
        ctx.Response.ContentLength64 = responseBytes.Length;
        ctx.Response.OutputStream.Write(responseBytes, 0, responseBytes.Length);
        ctx.Response.Close();
    }

    static string? FindGamePath(GameConfig config)
    {
        var paths = new[]
        {
            config.ClientPath,
            // Private copy first (completely separate from official install)
            @"D:\LeagueOfLegendsV2\client-private\Game",
            Path.Combine(Directory.GetCurrentDirectory(), "client-private", "Game"),
            // Fallback to original copy
            Path.Combine(Directory.GetCurrentDirectory(), "client", "Game"),
            @"D:\LeagueOfLegendsV2\client\Game",
            // Official install (last resort)
            @"D:\Programm\Riot Games\League of Legends\Game",
            @"D:\Riot Games\League of Legends\Game",
            @"C:\Riot Games\League of Legends\Game",
        };

        foreach (var path in paths)
        {
            if (!string.IsNullOrEmpty(path) && File.Exists(Path.Combine(path, "League of Legends.exe")))
                return path;
        }

        return null;
    }

    static string FindRepoRoot()
    {
        var dir = Directory.GetCurrentDirectory();
        for (int i = 0; i < 10; i++)
        {
            if (File.Exists(Path.Combine(dir, "start-server.bat")) || Directory.Exists(Path.Combine(dir, "server")))
                return dir;
            var parent = Directory.GetParent(dir);
            if (parent == null) break;
            dir = parent.FullName;
        }
        return Directory.GetCurrentDirectory();
    }

    static string? FindConfigPath()
    {
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

        return null;
    }

    static string? GetLatestDirectory(string parentDir)
    {
        string? latest = null;
        DateTime latestTime = DateTime.MinValue;

        foreach (var dir in Directory.GetDirectories(parentDir))
        {
            var info = new DirectoryInfo(dir);
            if (info.CreationTime > latestTime)
            {
                latestTime = info.CreationTime;
                latest = dir;
            }
        }

        return latest;
    }

    /// <summary>
    /// Patch the exe to strip Riot's digital signature and PE checksum.
    /// This prevents the Vanguard kernel driver (vgk.sys) from recognizing
    /// and blocking our copy as a "known Riot binary".
    /// </summary>
    static void PatchExeForPrivateServer(string exePath)
    {
        var bytes = File.ReadAllBytes(exePath);

        // PE header offset at 0x3C
        int peOffset = BitConverter.ToInt32(bytes, 0x3C);
        ushort peMagic = BitConverter.ToUInt16(bytes, peOffset + 0x18);

        // Certificate table directory entry offset
        int certOffset;
        if (peMagic == 0x20B) // PE32+ (64-bit)
            certOffset = peOffset + 0x18 + 0x70 + 0x20; // DataDirectory[4]
        else // PE32
            certOffset = peOffset + 0x18 + 0x60 + 0x20;

        uint certRVA = BitConverter.ToUInt32(bytes, certOffset);
        uint certSize = BitConverter.ToUInt32(bytes, certOffset + 4);

        System.Console.WriteLine($"  PE: {(peMagic == 0x20B ? "64-bit" : "32-bit")}");
        System.Console.WriteLine($"  Certificate: offset={certRVA} size={certSize}");

        // Zero out certificate directory entry
        for (int i = 0; i < 8; i++)
            bytes[certOffset + i] = 0;

        // Truncate appended certificate data
        if (certRVA > 0 && certRVA < bytes.Length)
        {
            var trimmed = new byte[certRVA];
            Array.Copy(bytes, trimmed, certRVA);
            bytes = trimmed;
            System.Console.WriteLine($"  Stripped {certSize} bytes of certificate data");
        }

        // Zero PE checksum
        int checksumOffset = peOffset + 0x18 + 0x40;
        for (int i = 0; i < 4; i++)
            bytes[checksumOffset + i] = 0;

        File.WriteAllBytes(exePath, bytes);
        System.Console.WriteLine($"  Patched: signature stripped, checksum zeroed");
    }
}

/// <summary>
/// Helper to find a free TCP port for the fake RiotClient.
/// </summary>
class TcpPortFinder
{
    public int FindFreePort()
    {
        var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}
