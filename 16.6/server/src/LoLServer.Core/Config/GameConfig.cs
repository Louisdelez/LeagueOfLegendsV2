using System.Collections.Generic;
using Newtonsoft.Json;

namespace LoLServer.Core.Config;

public class GameConfig
{
    [JsonProperty("gameMode")]
    public string GameMode { get; set; } = "CLASSIC";

    [JsonProperty("mapId")]
    public int MapId { get; set; } = 11; // Summoner's Rift

    [JsonProperty("serverPort")]
    public int ServerPort { get; set; } = 5119;

    [JsonProperty("clientPath")]
    public string ClientPath { get; set; } = "";

    [JsonProperty("blowfishKey")]
    public string BlowfishKey { get; set; } = "17BLOhi6KZsTtldTsizvHg==";

    [JsonProperty("gameVersion")]
    public string GameVersion { get; set; } = "16.6.1";

    [JsonProperty("players")]
    public List<PlayerConfig> Players { get; set; } = new()
    {
        new PlayerConfig
        {
            PlayerId = 1,
            Team = TeamId.Blue,
            Name = "Player1",
            Champion = "Ezreal",
            SkinId = 0,
            SummonerSpell1 = "SummonerFlash",
            SummonerSpell2 = "SummonerIgnite"
        }
    };

    public static GameConfig LoadFromFile(string path)
    {
        var json = System.IO.File.ReadAllText(path);
        return JsonConvert.DeserializeObject<GameConfig>(json) ?? new GameConfig();
    }

    public void SaveToFile(string path)
    {
        var json = JsonConvert.SerializeObject(this, Formatting.Indented);
        System.IO.File.WriteAllText(path, json);
    }
}

public class PlayerConfig
{
    [JsonProperty("playerId")]
    public ulong PlayerId { get; set; }

    [JsonProperty("team")]
    public TeamId Team { get; set; }

    [JsonProperty("name")]
    public string Name { get; set; } = "Player";

    [JsonProperty("champion")]
    public string Champion { get; set; } = "Ezreal";

    [JsonProperty("skinId")]
    public int SkinId { get; set; }

    [JsonProperty("summonerSpell1")]
    public string SummonerSpell1 { get; set; } = "SummonerFlash";

    [JsonProperty("summonerSpell2")]
    public string SummonerSpell2 { get; set; } = "SummonerIgnite";

    [JsonProperty("blowfishKey")]
    public string? BlowfishKey { get; set; }
}

public enum TeamId
{
    Blue = 100,
    Red = 200
}
