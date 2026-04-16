namespace LoLServer.Core.Protocol;

/// <summary>
/// Game packet IDs (first byte of decrypted payload).
/// Based on LeagueSandbox 4.20 opcodes.
/// Modern clients may use different values - raw capture mode helps identify them.
/// </summary>
public enum GamePacketId : byte
{
    // === Handshake / Loading ===
    KeyCheck = 0x00,
    SynchVersionC2S = 0x56,
    SynchVersionS2C = 0x1B,
    PingLoadInfoC2S = 0x17,
    PingLoadInfoS2C = 0x26,
    CharSelectedC2S = 0x52,
    ClientReadyC2S = 0x64,

    // === Spawn ===
    StartSpawnS2C = 0x11,
    EndSpawnS2C = 0x12,
    StartGameS2C = 0x35,
    CreateHeroS2C = 0x4C,
    CreateTurretS2C = 0x90,
    CreateMinionS2C = 0x95,
    CreateNeutralS2C = 0x96,

    // === Movement ===
    MovementRequestC2S = 0x72,
    MovementS2C = 0x61,
    StopMovementC2S = 0x37,
    WaypointListS2C = 0x62,

    // === Combat / Stats ===
    DamageDoneS2C = 0x06,
    SetHealthS2C = 0x48,
    LevelUpS2C = 0x1F,
    StatsUpdateS2C = 0x2A,
    NpcDieS2C = 0x3A,
    NpcRespawnS2C = 0x3B,

    // === Items ===
    BuyItemC2S = 0x10,
    SellItemC2S = 0x3C,
    SwapItemC2S = 0x60,
    ItemBuyS2C = 0x67,
    ItemRemoveS2C = 0x77,
    InventoryUpdateS2C = 0x7E,

    // === Abilities ===
    CastSpellC2S = 0x9A,
    CastSpellS2C = 0x9B,
    LevelUpSpellC2S = 0x39,
    LevelUpSpellS2C = 0x3F,
    SetCooldownS2C = 0x85,

    // === Economy ===
    GoldUpdateS2C = 0x28,

    // === Chat ===
    ChatMessageC2S = 0x68,
    ChatMessageS2C = 0x69,

    // === Time / Sync ===
    GameTimerS2C = 0xC0,
    GameTimerUpdateS2C = 0xC1,
    SyncClockC2S = 0xCA,
    SyncClockS2C = 0xCB,

    // === Announcements ===
    AnnounceS2C = 0x78,

    // === Vision ===
    FogUpdate2S2C = 0x4A,
    ChangeVisibilityS2C = 0x44,

    // === Emotes / Ping ===
    EmotionC2S = 0x36,
    PingC2S = 0x57,
    PingS2C = 0x40,

    // === Scoreboard ===
    ScoreboardUpdateS2C = 0x2E,

    // === Auto Attack ===
    AutoAttackC2S = 0x46,
    AttackTargetS2C = 0x47,
    StopAutoAttackC2S = 0x3D,

    // === Summoner Spells ===
    CastSummonerSpellC2S = 0x9C,

    // === Recall ===
    RecallC2S = 0x50,
    RecallS2C = 0x51,

    // === Surrender ===
    SurrenderVoteC2S = 0x31,
    SurrenderResultS2C = 0x32,
}

/// <summary>
/// Loading screen packet IDs (channel 7).
/// </summary>
public enum LoadScreenPacketId : byte
{
    RequestJoinTeam = 0x64,
    RequestReskin = 0x65,
    RequestRename = 0x66,
    TeamRosterUpdate = 0x01,
    PlayerNameUpdate = 0x02,
    PlayerChampionUpdate = 0x03
}

/// <summary>
/// Movement types for waypoint packets.
/// </summary>
public enum MovementType : byte
{
    Stop = 0x01,
    Waypoint = 0x02,
    AttackMove = 0x03,
}

/// <summary>
/// Announce event types.
/// </summary>
public enum AnnounceEvent : byte
{
    Welcome = 0x01,
    MinionSpawn = 0x02,
    TurretDestroyed = 0x03,
    InhibitorDestroyed = 0x04,
    InhibitorRespawning = 0x05,
    ChampionKill = 0x06,
    FirstBlood = 0x07,
    AceTeamBlue = 0x08,
    AceTeamRed = 0x09,
    Victory = 0x0A,
    Defeat = 0x0B,
    DragonKill = 0x0C,
    BaronKill = 0x0D,
    HeraldKill = 0x0E,
}
