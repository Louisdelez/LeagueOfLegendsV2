namespace LoLServer.Core.Protocol;

/// <summary>
/// Game packet IDs (first byte of decrypted payload).
/// Based on LeagueSandbox 4.20 opcodes - will need updating for modern client.
/// </summary>
public enum GamePacketId : byte
{
    KeyCheck = 0x00,
    SynchVersionC2S = 0x56,
    SynchVersionS2C = 0x1B,
    PingLoadInfoC2S = 0x17,
    PingLoadInfoS2C = 0x26,
    CharSelectedC2S = 0x52,
    ClientReadyC2S = 0x64,
    StartSpawnS2C = 0x11,
    EndSpawnS2C = 0x12,
    StartGameS2C = 0x35,
    CreateHeroS2C = 0x4C,
    CreateTurretS2C = 0x90,
    CreateMinionS2C = 0x95,
    MovementS2C = 0x61,
    DamageDoneS2C = 0x06,
    SetHealthS2C = 0x48,
    LevelUpS2C = 0x1F,
    ItemBuyS2C = 0x67,
    GoldUpdateS2C = 0x28,
    ChatMessageC2S = 0x68,
    ChatMessageS2C = 0x69,
    GameTimerS2C = 0xC0,
    GameTimerUpdateS2C = 0xC1,
    SetCooldownS2C = 0x85,
    NpcDieS2C = 0x3A,
    AnnounceS2C = 0x78
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
