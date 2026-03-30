using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using Newtonsoft.Json;
using LoLServer.Core.Config;

namespace LoLServer.Core.Lobby;

/// <summary>
/// Mini HTTP server for the lobby/champion select phase.
/// Players connect via a web browser to pick champions, runes, and summoner spells
/// before the game starts.
///
/// Endpoints:
///   GET  /                  - Lobby page (HTML)
///   GET  /api/lobby         - Current lobby state (JSON)
///   POST /api/join          - Join the lobby
///   POST /api/champion      - Pick a champion
///   POST /api/spells        - Set summoner spells
///   POST /api/team          - Switch team
///   POST /api/ready         - Toggle ready state
///   POST /api/start         - Start the game (host only)
///   GET  /api/champions     - List available champions
/// </summary>
public class LobbyServer : IDisposable
{
    private readonly HttpListener _listener;
    private readonly int _port;
    private readonly LobbyState _state;
    private bool _running;
    private Thread? _thread;

    public event Action<GameConfig>? OnGameStart;

    public LobbyServer(int port = 8080)
    {
        _port = port;
        _listener = new HttpListener();
        _listener.Prefixes.Add($"http://+:{port}/");
        _state = new LobbyState();
    }

    public void Start()
    {
        _running = true;
        _listener.Start();
        _thread = new Thread(ListenLoop) { IsBackground = true, Name = "LobbyHTTP" };
        _thread.Start();
        Console.WriteLine($"[LOBBY] Web lobby running at http://localhost:{_port}/");
        Console.WriteLine($"[LOBBY] Players can join at http://<YOUR_IP>:{_port}/");
    }

    private void ListenLoop()
    {
        while (_running)
        {
            try
            {
                var ctx = _listener.GetContext();
                ThreadPool.QueueUserWorkItem(_ => HandleRequest(ctx));
            }
            catch (HttpListenerException) when (!_running)
            {
                break;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[LOBBY] Error: {ex.Message}");
            }
        }
    }

    private void HandleRequest(HttpListenerContext ctx)
    {
        var req = ctx.Request;
        var res = ctx.Response;

        try
        {
            var path = req.Url?.AbsolutePath ?? "/";
            var method = req.HttpMethod;

            // CORS
            res.Headers.Add("Access-Control-Allow-Origin", "*");
            res.Headers.Add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            res.Headers.Add("Access-Control-Allow-Headers", "Content-Type");

            if (method == "OPTIONS")
            {
                res.StatusCode = 200;
                res.Close();
                return;
            }

            string responseBody;

            switch (path)
            {
                case "/":
                    responseBody = GetLobbyHtml();
                    res.ContentType = "text/html; charset=utf-8";
                    break;

                case "/api/lobby":
                    responseBody = JsonConvert.SerializeObject(_state);
                    res.ContentType = "application/json";
                    break;

                case "/api/champions":
                    responseBody = JsonConvert.SerializeObject(ChampionList.All);
                    res.ContentType = "application/json";
                    break;

                case "/api/join" when method == "POST":
                    responseBody = HandleJoin(ReadBody(req));
                    res.ContentType = "application/json";
                    break;

                case "/api/champion" when method == "POST":
                    responseBody = HandleChampionPick(ReadBody(req));
                    res.ContentType = "application/json";
                    break;

                case "/api/spells" when method == "POST":
                    responseBody = HandleSpells(ReadBody(req));
                    res.ContentType = "application/json";
                    break;

                case "/api/team" when method == "POST":
                    responseBody = HandleTeamSwitch(ReadBody(req));
                    res.ContentType = "application/json";
                    break;

                case "/api/ready" when method == "POST":
                    responseBody = HandleReady(ReadBody(req));
                    res.ContentType = "application/json";
                    break;

                case "/api/start" when method == "POST":
                    responseBody = HandleStart();
                    res.ContentType = "application/json";
                    break;

                default:
                    res.StatusCode = 404;
                    responseBody = "{\"error\":\"Not found\"}";
                    res.ContentType = "application/json";
                    break;
            }

            var buffer = Encoding.UTF8.GetBytes(responseBody);
            res.ContentLength64 = buffer.Length;
            res.OutputStream.Write(buffer, 0, buffer.Length);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[LOBBY] Request error: {ex.Message}");
            res.StatusCode = 500;
        }
        finally
        {
            res.Close();
        }
    }

    private string HandleJoin(string body)
    {
        var data = JsonConvert.DeserializeAnonymousType(body, new { name = "" });
        if (string.IsNullOrEmpty(data?.name))
            return "{\"error\":\"Name required\"}";

        if (_state.Players.Count >= 10)
            return "{\"error\":\"Lobby full (10 players max)\"}";

        if (_state.Players.Any(p => p.Name == data.name))
            return "{\"error\":\"Name already taken\"}";

        var player = new LobbyPlayer
        {
            Id = _state.NextPlayerId++,
            Name = data.name,
            Team = _state.Players.Count(p => p.Team == TeamId.Blue) <= _state.Players.Count(p => p.Team == TeamId.Red)
                ? TeamId.Blue : TeamId.Red,
            Champion = "Ezreal",
            IsReady = false
        };

        _state.Players.Add(player);
        Console.WriteLine($"[LOBBY] {player.Name} joined ({player.Team} team)");

        return JsonConvert.SerializeObject(new { success = true, player });
    }

    private string HandleChampionPick(string body)
    {
        var data = JsonConvert.DeserializeAnonymousType(body, new { playerId = 0, champion = "" });
        var player = _state.Players.FirstOrDefault(p => p.Id == data?.playerId);
        if (player == null) return "{\"error\":\"Player not found\"}";

        player.Champion = data!.champion;
        Console.WriteLine($"[LOBBY] {player.Name} picked {player.Champion}");
        return JsonConvert.SerializeObject(new { success = true });
    }

    private string HandleSpells(string body)
    {
        var data = JsonConvert.DeserializeAnonymousType(body, new { playerId = 0, spell1 = "", spell2 = "" });
        var player = _state.Players.FirstOrDefault(p => p.Id == data?.playerId);
        if (player == null) return "{\"error\":\"Player not found\"}";

        player.SummonerSpell1 = data!.spell1;
        player.SummonerSpell2 = data.spell2;
        return JsonConvert.SerializeObject(new { success = true });
    }

    private string HandleTeamSwitch(string body)
    {
        var data = JsonConvert.DeserializeAnonymousType(body, new { playerId = 0 });
        var player = _state.Players.FirstOrDefault(p => p.Id == data?.playerId);
        if (player == null) return "{\"error\":\"Player not found\"}";

        var targetTeam = player.Team == TeamId.Blue ? TeamId.Red : TeamId.Blue;
        if (_state.Players.Count(p => p.Team == targetTeam) >= 5)
            return "{\"error\":\"Team full\"}";

        player.Team = targetTeam;
        Console.WriteLine($"[LOBBY] {player.Name} switched to {player.Team}");
        return JsonConvert.SerializeObject(new { success = true });
    }

    private string HandleReady(string body)
    {
        var data = JsonConvert.DeserializeAnonymousType(body, new { playerId = 0 });
        var player = _state.Players.FirstOrDefault(p => p.Id == data?.playerId);
        if (player == null) return "{\"error\":\"Player not found\"}";

        player.IsReady = !player.IsReady;
        Console.WriteLine($"[LOBBY] {player.Name} is {(player.IsReady ? "READY" : "not ready")}");
        return JsonConvert.SerializeObject(new { success = true, ready = player.IsReady });
    }

    private string HandleStart()
    {
        if (_state.Players.Count == 0)
            return "{\"error\":\"No players\"}";

        Console.WriteLine($"[LOBBY] Starting game with {_state.Players.Count} players!");

        // Build GameConfig from lobby state
        var config = new GameConfig
        {
            GameMode = _state.GameMode,
            MapId = _state.MapId,
            Players = _state.Players.Select((p, i) => new PlayerConfig
            {
                PlayerId = (ulong)(i + 1),
                Team = p.Team,
                Name = p.Name,
                Champion = p.Champion,
                SkinId = 0,
                SummonerSpell1 = p.SummonerSpell1,
                SummonerSpell2 = p.SummonerSpell2,
            }).ToList()
        };

        _state.GameStarted = true;
        OnGameStart?.Invoke(config);

        return JsonConvert.SerializeObject(new { success = true, message = "Game starting!" });
    }

    private static string ReadBody(HttpListenerRequest req)
    {
        using var reader = new StreamReader(req.InputStream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    private string GetLobbyHtml()
    {
        return @"<!DOCTYPE html>
<html><head>
<meta charset=""utf-8""><title>LoL Private Server - Lobby</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family: 'Segoe UI',sans-serif; background:#0a1428; color:#c8aa6e; min-height:100vh; }
  .header { background:#1e2328; padding:20px; text-align:center; border-bottom:2px solid #c8aa6e; }
  .header h1 { font-size:28px; color:#f0e6d2; }
  .header p { color:#a09b8c; margin-top:5px; }
  .container { max-width:1200px; margin:20px auto; padding:0 20px; }
  .join-form { text-align:center; margin:30px 0; }
  .join-form input { padding:12px 20px; font-size:16px; background:#1e2328; border:1px solid #463714; color:#f0e6d2; border-radius:4px; width:250px; }
  .join-form button { padding:12px 30px; font-size:16px; background:#c8aa6e; color:#1e2328; border:none; border-radius:4px; cursor:pointer; font-weight:bold; margin-left:10px; }
  .join-form button:hover { background:#f0e6d2; }
  .teams { display:flex; gap:40px; justify-content:center; margin:30px 0; }
  .team { flex:1; max-width:450px; background:#1e2328; border-radius:8px; padding:20px; border:2px solid #463714; }
  .team.blue { border-color:#0596aa; }
  .team.red { border-color:#be1e37; }
  .team h2 { text-align:center; margin-bottom:15px; font-size:20px; }
  .team.blue h2 { color:#0596aa; }
  .team.red h2 { color:#be1e37; }
  .player { display:flex; align-items:center; padding:10px; margin:5px 0; background:#0a1428; border-radius:4px; border:1px solid #463714; }
  .player .name { flex:1; font-size:16px; color:#f0e6d2; }
  .player .champ { color:#c8aa6e; font-size:14px; margin-right:10px; }
  .player .ready { color:#1cad1c; font-weight:bold; }
  .player .not-ready { color:#666; }
  .controls { text-align:center; margin:30px 0; }
  .controls select, .controls button { padding:10px 20px; font-size:14px; margin:5px; background:#1e2328; color:#f0e6d2; border:1px solid #463714; border-radius:4px; cursor:pointer; }
  .controls button.start { background:#1cad1c; color:#fff; font-size:18px; padding:15px 50px; }
  .controls button.start:hover { background:#25d025; }
  .mode-select { text-align:center; margin:20px 0; }
  .mode-select button { padding:10px 25px; margin:5px; background:#1e2328; color:#c8aa6e; border:1px solid #463714; border-radius:4px; cursor:pointer; }
  .mode-select button.active { background:#463714; color:#f0e6d2; border-color:#c8aa6e; }
  #status { text-align:center; margin:15px; color:#a09b8c; font-size:14px; }
</style>
</head><body>
<div class=""header"">
  <h1>LoL Private Server</h1>
  <p>Champion Select - Pick your champion and get ready!</p>
</div>
<div class=""container"">
  <div class=""join-form"" id=""joinForm"">
    <input id=""nameInput"" placeholder=""Enter your summoner name..."" />
    <button onclick=""joinLobby()"">Join Lobby</button>
  </div>
  <div class=""mode-select"">
    <button class=""active"" onclick=""setMode(11,'CLASSIC')"">Summoner's Rift (5v5)</button>
    <button onclick=""setMode(12,'ARAM')"">ARAM</button>
    <button onclick=""setMode(10,'CLASSIC')"">Twisted Treeline (3v3)</button>
  </div>
  <div id=""status"">Waiting for players...</div>
  <div class=""teams"">
    <div class=""team blue""><h2>Blue Team</h2><div id=""blueTeam""></div></div>
    <div class=""team red""><h2>Red Team</h2><div id=""redTeam""></div></div>
  </div>
  <div class=""controls"" id=""playerControls"" style=""display:none"">
    <select id=""champSelect"" onchange=""pickChampion()""></select>
    <select id=""spell1""><option>SummonerFlash</option><option>SummonerIgnite</option><option>SummonerHeal</option><option>SummonerBarrier</option><option>SummonerTeleport</option><option>SummonerSmite</option><option>SummonerExhaust</option><option>SummonerGhost</option><option>SummonerCleanse</option></select>
    <select id=""spell2""><option>SummonerIgnite</option><option>SummonerFlash</option><option>SummonerHeal</option><option>SummonerBarrier</option><option>SummonerTeleport</option><option>SummonerSmite</option><option>SummonerExhaust</option><option>SummonerGhost</option><option>SummonerCleanse</option></select>
    <button onclick=""setSpells()"">Set Spells</button>
    <button onclick=""switchTeam()"">Switch Team</button>
    <button onclick=""toggleReady()"">Ready / Not Ready</button>
    <br><br>
    <button class=""start"" onclick=""startGame()"">START GAME</button>
  </div>
</div>
<script>
let myId = null;
const API = '';

async function joinLobby() {
  const name = document.getElementById('nameInput').value.trim();
  if (!name) return;
  const r = await fetch(API+'/api/join',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})});
  const d = await r.json();
  if (d.success) {
    myId = d.player.id;
    document.getElementById('joinForm').style.display='none';
    document.getElementById('playerControls').style.display='block';
    loadChampions();
    setInterval(refreshLobby, 1000);
  } else { alert(d.error); }
}

async function loadChampions() {
  const r = await fetch(API+'/api/champions');
  const champs = await r.json();
  const sel = document.getElementById('champSelect');
  sel.innerHTML = champs.map(c=>`<option>${c}</option>`).join('');
}

async function pickChampion() {
  const champ = document.getElementById('champSelect').value;
  await fetch(API+'/api/champion',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({playerId:myId,champion:champ})});
}

async function setSpells() {
  await fetch(API+'/api/spells',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({playerId:myId,spell1:document.getElementById('spell1').value,spell2:document.getElementById('spell2').value})});
}

async function switchTeam() {
  await fetch(API+'/api/team',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({playerId:myId})});
}

async function toggleReady() {
  await fetch(API+'/api/ready',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({playerId:myId})});
}

async function startGame() {
  const r = await fetch(API+'/api/start',{method:'POST'});
  const d = await r.json();
  if (d.success) { document.getElementById('status').innerHTML='<b style=""color:#1cad1c"">GAME STARTING!</b>'; }
  else { alert(d.error); }
}

function setMode(mapId, mode) {
  document.querySelectorAll('.mode-select button').forEach(b=>b.classList.remove('active'));
  event.target.classList.add('active');
}

async function refreshLobby() {
  const r = await fetch(API+'/api/lobby');
  const s = await r.json();
  const blue = s.Players.filter(p=>p.Team===100);
  const red = s.Players.filter(p=>p.Team===200);
  document.getElementById('blueTeam').innerHTML = blue.map(renderPlayer).join('');
  document.getElementById('redTeam').innerHTML = red.map(renderPlayer).join('');
  document.getElementById('status').textContent = `${s.Players.length}/10 players | ${blue.length}v${red.length}`;
  if(s.GameStarted) document.getElementById('status').innerHTML='<b style=""color:#1cad1c"">GAME STARTED!</b>';
}

function renderPlayer(p) {
  const ready = p.IsReady ? '<span class=""ready"">READY</span>' : '<span class=""not-ready"">...</span>';
  const me = p.Id===myId ? ' style=""border-color:#c8aa6e""' : '';
  return `<div class=""player""${me}><span class=""name"">${p.Name}</span><span class=""champ"">${p.Champion}</span>${ready}</div>`;
}
</script>
</body></html>";
    }

    public void Stop()
    {
        _running = false;
        _listener.Stop();
    }

    public void Dispose()
    {
        Stop();
    }
}

public class LobbyState
{
    public List<LobbyPlayer> Players { get; set; } = new();
    public string GameMode { get; set; } = "CLASSIC";
    public int MapId { get; set; } = 11;
    public bool GameStarted { get; set; }
    public int NextPlayerId { get; set; } = 1;
}

public class LobbyPlayer
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public TeamId Team { get; set; }
    public string Champion { get; set; } = "Ezreal";
    public string SummonerSpell1 { get; set; } = "SummonerFlash";
    public string SummonerSpell2 { get; set; } = "SummonerIgnite";
    public bool IsReady { get; set; }
}

/// <summary>
/// All available champion names (164 champions from the modern client).
/// </summary>
public static class ChampionList
{
    public static readonly string[] All =
    {
        "Aatrox","Ahri","Akali","Akshan","Alistar","Ambessa","Amumu","Anivia","Annie","Aphelios",
        "Ashe","AurelionSol","Aurora","Azir","Bard","Belveth","Blitzcrank","Brand","Braum","Briar",
        "Caitlyn","Camille","Cassiopeia","Chogath","Corki","Darius","Diana","Draven","DrMundo","Ekko",
        "Elise","Evelynn","Ezreal","Fiddlesticks","Fiora","Fizz","Galio","Gangplank","Garen","Gnar",
        "Gragas","Graves","Gwen","Hecarim","Heimerdinger","Hwei","Illaoi","Irelia","Ivern","Janna",
        "JarvanIV","Jax","Jayce","Jhin","Jinx","KSante","Kaisa","Kalista","Karma","Karthus",
        "Kassadin","Katarina","Kayle","Kayn","Kennen","Khazix","Kindred","Kled","KogMaw","LeBlanc",
        "LeeSin","Leona","Lillia","Lissandra","Lucian","Lulu","Lux","Malphite","Malzahar","Maokai",
        "MasterYi","Mel","Milio","MissFortune","MonkeyKing","Mordekaiser","Morgana","Naafiri","Nami",
        "Nasus","Nautilus","Neeko","Nidalee","Nilah","Nocturne","Nunu","Olaf","Orianna","Ornn",
        "Pantheon","Poppy","Pyke","Qiyana","Quinn","Rakan","Rammus","RekSai","Rell","Renata",
        "Renekton","Rengar","Riven","Rumble","Ryze","Samira","Sejuani","Senna","Seraphine","Sett",
        "Shaco","Shen","Shyvana","Singed","Sion","Sivir","Skarner","Smolder","Sona","Soraka",
        "Swain","Sylas","Syndra","TahmKench","Taliyah","Talon","Taric","Teemo","Thresh","Tristana",
        "Trundle","Tryndamere","TwistedFate","Twitch","Udyr","Urgot","Varus","Vayne","Veigar",
        "Velkoz","Vex","Vi","Viego","Viktor","Vladimir","Volibear","Warwick","Xayah","Xerath",
        "XinZhao","Yasuo","Yone","Yorick","Yuumi","Zac","Zed","Zeri","Ziggs","Zilean","Zoe","Zyra"
    };
}
