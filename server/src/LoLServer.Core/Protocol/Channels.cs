namespace LoLServer.Core.Protocol;

/// <summary>
/// League of Legends ENet channel definitions.
/// The game uses 8 named channels over the ENet connection.
/// </summary>
public enum Channel : byte
{
    /// <summary>KeyCheck handshake - NEVER encrypted</summary>
    Handshake = 0,

    /// <summary>Client-to-server game commands (movement, cast, etc.)</summary>
    ClientToServer = 1,

    /// <summary>Gameplay state updates (time sync, world state)</summary>
    Gameplay = 2,

    /// <summary>Server-to-client responses (state updates, notifications)</summary>
    ServerToClient = 3,

    /// <summary>Low-priority data</summary>
    LowPriority = 4,

    /// <summary>Chat messages</summary>
    Communication = 5,

    /// <summary>Loading screen packets (JoinTeam, Reskin, Rename)</summary>
    LoadingScreen = 7
}
