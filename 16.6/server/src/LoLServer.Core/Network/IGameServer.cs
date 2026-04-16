using LoLServer.Core.Config;
using LoLServer.Core.Protocol;

namespace LoLServer.Core.Network;

/// <summary>
/// Interface for game servers that can send packets to clients.
/// Implemented by both PacketServer (LENet) and RawGameServer (raw UDP).
/// </summary>
public interface IGameServer
{
    IReadOnlyDictionary<ushort, ClientInfo> Clients { get; }

    void SendPacket(ClientInfo client, byte[] data, Channel channel);
    void BroadcastPacket(byte[] data, Channel channel);
    void BroadcastPacketToTeam(byte[] data, Channel channel, TeamId team);
}
