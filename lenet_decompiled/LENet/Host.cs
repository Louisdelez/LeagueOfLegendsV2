using System;
using System.Net;
using System.Net.Sockets;

namespace LENet;

public sealed class Host : IDisposable
{
	public const uint RECEIVE_BUFFER_SIZE = 262144u;

	public const uint SEND_BUFFER_SIZE = 262144u;

	public const ushort DEFAULT_MTU = 996;

	public const ushort MINIMUM_MTU = 576;

	public const ushort MAXIMUM_MTU = 4096;

	public const ushort MINIMUM_WINDOW_SIZE = 4096;

	public const ushort MAXIMUM_WINDOW_SIZE = 32768;

	public const byte MINIMUM_CHANNEL_COUNT = 1;

	public const byte MAXIMUM_CHANNEL_COUNT = byte.MaxValue;

	public const byte MAXIMUM_PEER_ID = 127;

	private uint _nextSessionID = 1u;

	private readonly int _timeStart = Environment.TickCount;

	public Version Version { get; }

	public Socket Socket { get; }

	public uint IncomingBandwidth { get; set; }

	public uint OutgoingBandwidth { get; set; }

	public uint BandwidthThrottleEpoch { get; set; }

	public uint MTU { get; set; }

	public bool RecalculateBandwidthLimits { get; set; }

	public Peer[] Peers { get; }

	public uint PeerCount => (uint)Peers.Length;

	public uint ChannelLimit { get; set; }

	public uint ServiceTime { get; set; }

	public LList<Peer> DispatchQueue { get; } = new LList<Peer>();

	public uint TotalSentData { get; set; }

	public uint TotalSentPackets { get; set; }

	public uint TotalReceivedData { get; set; }

	public uint TotalReceivedPackets { get; set; }

	public uint GetTime()
	{
		return (uint)(Environment.TickCount - _timeStart);
	}

	public Host(Version version, Address? address, uint peerCount, uint channelCount = 0u, uint incomingBandwith = 0u, uint outgoingBandwith = 0u, ushort mtu = 0)
	{
		if (peerCount > version.MaxPeerID)
		{
			throw new ArgumentOutOfRangeException("peerCount");
		}
		channelCount = ((channelCount == 0) ? 255u : channelCount);
		channelCount = Utils.Clamp(channelCount, 1u, 255u);
		mtu = (ushort)((mtu == 0) ? 996 : mtu);
		mtu = Utils.Clamp(mtu, 576, 4096);
		Socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.IP);
		if (address.HasValue)
		{
			Address valueOrDefault = address.GetValueOrDefault();
			if (true)
			{
				try
				{
					Socket.Bind(new IPEndPoint(valueOrDefault.Host, valueOrDefault.Port));
				}
				catch (Exception ex)
				{
					Socket.Dispose();
					throw ex;
				}
			}
		}
		Socket.Blocking = false;
		Socket.EnableBroadcast = true;
		Socket.ReceiveBufferSize = 262144;
		Socket.SendBufferSize = 262144;
		Version = version;
		ChannelLimit = channelCount;
		IncomingBandwidth = incomingBandwith;
		OutgoingBandwidth = outgoingBandwith;
		MTU = mtu;
		Peers = new Peer[peerCount];
		for (int i = 0; i < peerCount; i++)
		{
			Peers[i] = new Peer(this, (ushort)i);
		}
	}

	public void Dispose()
	{
		Socket.Dispose();
	}

	public Peer Connect(Address address, uint channelCount = 0u)
	{
		channelCount = ((channelCount == 0) ? ChannelLimit : channelCount);
		channelCount = Utils.Clamp(channelCount, 1u, ChannelLimit);
		Peer peer = Array.Find(Peers, (Peer p) => p.State == PeerState.DISCONNECTED);
		if (peer == null)
		{
			return null;
		}
		peer.ResetChannels();
		peer.ChannelCount = channelCount;
		peer.State = PeerState.CONNECTING;
		peer.Address = address;
		peer.SessionID = _nextSessionID++;
		if (Version.MaxPeerID == 127)
		{
			peer.SessionID &= 255u;
		}
		if (OutgoingBandwidth == 0)
		{
			peer.WindowSize = 32768u;
		}
		else
		{
			peer.WindowSize = OutgoingBandwidth / 65536 * 4096;
		}
		peer.WindowSize = Utils.Clamp(peer.WindowSize, 4096u, 32768u);
		Protocol.Connect command = new Protocol.Connect
		{
			Flags = ProtocolFlag.ACKNOWLEDGE,
			ChannelID = byte.MaxValue,
			OutgoingPeerID = peer.IncomingPeerID,
			MTU = peer.MTU,
			WindowSize = peer.WindowSize,
			ChannelCount = channelCount,
			IncomingBandwidth = IncomingBandwidth,
			OutgoingBandwidth = OutgoingBandwidth,
			PacketThrottleInterval = peer.PacketThrottleInterval,
			PacketThrottleAcceleration = peer.PacketThrottleAcceleration,
			PacketThrottleDeceleration = peer.PacketThrottleDeceleration,
			SessionID = peer.SessionID
		};
		peer.QueueOutgoingCommand(command, null, 0u, 0);
		return peer;
	}

	public void SetChannelLimit(uint channelLimit)
	{
		if (channelLimit == 0)
		{
			channelLimit = 255u;
		}
		ChannelLimit = Utils.Clamp(channelLimit, 1u, 255u);
	}

	public void Broadcast(byte channelID, Packet packet)
	{
		Peer[] peers = Peers;
		foreach (Peer peer in peers)
		{
			if (peer.State == PeerState.CONNECTED)
			{
				peer.Send(channelID, packet);
			}
		}
	}

	public void SetBandwidthLimit(uint incomingBandwidth, uint outgoingBandwidth)
	{
		IncomingBandwidth = incomingBandwidth;
		OutgoingBandwidth = outgoingBandwidth;
		RecalculateBandwidthLimits = true;
	}

	public void BandwidthThrottle()
	{
		uint time = GetTime();
		uint num = time - BandwidthThrottleEpoch;
		if (num < Version.BandwidthThrottleInterval)
		{
			return;
		}
		uint num2 = 0u;
		uint num3 = 0u;
		Peer[] peers = Peers;
		foreach (Peer peer in peers)
		{
			if (peer.State == PeerState.CONNECTED || peer.State == PeerState.DISCONNECT_LATER)
			{
				num2++;
				num3 += peer.OutgoingDataTotal;
			}
		}
		if (num2 == 0)
		{
			return;
		}
		uint num4 = num2;
		bool flag = true;
		uint num5 = ((OutgoingBandwidth == 0) ? uint.MaxValue : (OutgoingBandwidth * num / 1000));
		uint num6 = 0u;
		while (num4 != 0 && flag)
		{
			flag = false;
			num6 = ((num3 >= num5) ? (num5 * 32 / num3) : 32u);
			Peer[] peers2 = Peers;
			foreach (Peer peer2 in peers2)
			{
				uint num7 = 0u;
				if ((peer2.State != PeerState.CONNECTED && peer2.State != PeerState.DISCONNECT_LATER) || peer2.IncomingBandwidth == 0 || peer2.OutgoingBandwidthThrottleEpoch == time)
				{
					continue;
				}
				num7 = peer2.IncomingBandwidth * num / 1000;
				if (num6 * peer2.OutgoingDataTotal / 32 > num7)
				{
					peer2.PacketThrottleLimit = num7 * 32 / peer2.OutgoingDataTotal;
					if (peer2.PacketThrottleLimit == 0)
					{
						peer2.PacketThrottleLimit = 1u;
					}
					if (peer2.PacketThrottle > peer2.PacketThrottleLimit)
					{
						peer2.PacketThrottle = peer2.PacketThrottleLimit;
					}
					peer2.OutgoingBandwidthThrottleEpoch = time;
					flag = true;
					num4--;
					num5 -= num7;
					num3 -= num7;
				}
			}
		}
		if (num4 != 0)
		{
			Peer[] peers3 = Peers;
			foreach (Peer peer3 in peers3)
			{
				if ((peer3.State == PeerState.CONNECTED || peer3.State == PeerState.DISCONNECT_LATER) && peer3.OutgoingBandwidthThrottleEpoch != time)
				{
					peer3.PacketThrottleLimit = num6;
					if (peer3.PacketThrottle > peer3.PacketThrottleLimit)
					{
						peer3.PacketThrottle = peer3.PacketThrottleLimit;
					}
				}
			}
		}
		if (RecalculateBandwidthLimits)
		{
			RecalculateBandwidthLimits = false;
			num4 = num2;
			num5 = IncomingBandwidth;
			flag = true;
			uint num8 = 0u;
			if (num5 != 0)
			{
				while (num4 != 0 && flag)
				{
					flag = false;
					num8 = num5 / num4;
					Peer[] peers4 = Peers;
					foreach (Peer peer4 in peers4)
					{
						if ((peer4.State == PeerState.CONNECTED || peer4.State == PeerState.DISCONNECT_LATER) && peer4.IncomingBandwidthThrottleEpoch != time && (peer4.OutgoingBandwidth == 0 || peer4.OutgoingBandwidth < num8))
						{
							peer4.IncomingBandwidthThrottleEpoch = time;
							flag = true;
							num4--;
							num5 -= peer4.OutgoingBandwidth;
						}
					}
				}
			}
			Peer[] peers5 = Peers;
			foreach (Peer peer5 in peers5)
			{
				if (peer5.State == PeerState.CONNECTED || peer5.State == PeerState.DISCONNECT_LATER)
				{
					Protocol.BandwidthLimit bandwidthLimit = new Protocol.BandwidthLimit
					{
						Flags = ProtocolFlag.ACKNOWLEDGE,
						ChannelID = byte.MaxValue,
						OutgoingBandwidth = OutgoingBandwidth
					};
					if (peer5.IncomingBandwidthThrottleEpoch == time)
					{
						bandwidthLimit.IncomingBandwidth = peer5.OutgoingBandwidth;
					}
					else
					{
						bandwidthLimit.IncomingBandwidth = num8;
					}
					peer5.QueueOutgoingCommand(bandwidthLimit, null, 0u, 0);
				}
			}
		}
		BandwidthThrottleEpoch = time;
		Peer[] peers6 = Peers;
		foreach (Peer peer6 in peers6)
		{
			peer6.IncomingDataTotal = 0u;
			peer6.OutgoingDataTotal = 0u;
		}
	}

	private int DispatchIncomingCommands(Event evnt)
	{
		while (!DispatchQueue.Empty)
		{
			Peer value = DispatchQueue.Begin.Remove().Value;
			value.NeedsDispatch = false;
			switch (value.State)
			{
			case PeerState.CONNECTION_PENDING:
			case PeerState.CONNECTION_SUCCEEDED:
				value.State = PeerState.CONNECTED;
				evnt.Type = EventType.CONNECT;
				evnt.Peer = value;
				return 1;
			case PeerState.ZOMBIE:
				RecalculateBandwidthLimits = true;
				evnt.Type = EventType.DISCONNECT;
				evnt.Peer = value;
				evnt.Data = value.DisconnectData;
				value.Reset();
				return 1;
			case PeerState.CONNECTED:
			{
				if (value.DispatchedCommands.Empty)
				{
					break;
				}
				evnt.Packet = value.Recieve(out var ChannelID);
				if (evnt.Packet == null)
				{
					break;
				}
				evnt.ChannelID = ChannelID;
				evnt.Type = EventType.RECEIVE;
				evnt.Peer = value;
				if (!value.DispatchedCommands.Empty)
				{
					value.NeedsDispatch = true;
					DispatchQueue.End.Insert(value.Node);
				}
				return 1;
			}
			}
		}
		return 0;
	}

	private void DispatchState(Peer peer, PeerState state)
	{
		peer.State = state;
		if (!peer.NeedsDispatch)
		{
			DispatchQueue.End.Insert(peer.Node);
			peer.NeedsDispatch = true;
		}
	}

	private void NotifyConnect(Peer peer, Event evnt)
	{
		RecalculateBandwidthLimits = true;
		if (evnt != null)
		{
			peer.State = PeerState.CONNECTED;
			evnt.Type = EventType.CONNECT;
			evnt.Peer = peer;
		}
		else
		{
			DispatchState(peer, (peer.State == PeerState.CONNECTING) ? PeerState.CONNECTION_SUCCEEDED : PeerState.CONNECTION_PENDING);
		}
	}

	private void NotifyDisconnect(Peer peer, Event evnt)
	{
		if (peer.State >= PeerState.CONNECTION_PENDING)
		{
			RecalculateBandwidthLimits = true;
		}
		if (peer.State != PeerState.CONNECTING && peer.State < PeerState.CONNECTION_SUCCEEDED)
		{
			peer.Reset();
		}
		else if (evnt != null)
		{
			evnt.Type = EventType.DISCONNECT;
			evnt.Peer = peer;
			evnt.Data = 0u;
			peer.Reset();
		}
		else
		{
			DispatchState(peer, PeerState.ZOMBIE);
		}
	}

	private static void RemoveSentUnreliableCommands(Peer peer)
	{
		peer.SentUnreliableCommands.Clear();
	}

	private static ProtocolCommand RemoveSentReliableCommand(Peer peer, ushort reliableSequenceNumber, byte channelID)
	{
		OutgoingCommand outgoingCommand = null;
		bool flag = true;
		LList<OutgoingCommand>.Node node;
		for (node = peer.SentReliableCommands.Begin; node != peer.SentReliableCommands.End; node = node.Next)
		{
			outgoingCommand = node.Value;
			if (outgoingCommand.ReliableSequenceNumber == reliableSequenceNumber && outgoingCommand.Command.ChannelID == channelID)
			{
				break;
			}
		}
		if (node == peer.SentReliableCommands.End)
		{
			for (node = peer.OutgoingReliableCommands.Begin; node != peer.OutgoingReliableCommands.End; node = node.Next)
			{
				outgoingCommand = node.Value;
				if (outgoingCommand.SendAttempts < 1)
				{
					return ProtocolCommand.NONE;
				}
				if (outgoingCommand.ReliableSequenceNumber == reliableSequenceNumber && outgoingCommand.Command.ChannelID == channelID)
				{
					break;
				}
			}
			if (node == peer.OutgoingReliableCommands.End)
			{
				return ProtocolCommand.NONE;
			}
			flag = false;
		}
		if (channelID < peer.ChannelCount)
		{
			Channel channel = peer.Channels[channelID];
			ushort num = (ushort)(reliableSequenceNumber / 4096);
			if (channel.ReliableWindows[num] > 0)
			{
				channel.ReliableWindows[num]--;
				if (channel.ReliableWindows[num] == 0)
				{
					channel.UsedReliableWindows &= (ushort)(~(1 << (int)num));
				}
			}
		}
		ProtocolCommand command = outgoingCommand.Command.Command;
		outgoingCommand.Node.Remove();
		if (outgoingCommand.Packet != null && flag)
		{
			peer.ReliableDataInTransit -= outgoingCommand.FragmentLength;
		}
		if (peer.SentReliableCommands.Empty)
		{
			return command;
		}
		outgoingCommand = peer.SentReliableCommands.Begin.Value;
		peer.NextTimeout = outgoingCommand.SentTime + outgoingCommand.RoundTripTimeout;
		return command;
	}

	private int HandleConnect(Address receivedAddress, ref Peer result, Protocol.Connect command)
	{
		uint num = command.ChannelCount;
		if (num < 1 || num > 255)
		{
			return -1;
		}
		Peer[] peers = Peers;
		foreach (Peer peer in peers)
		{
			if (peer.State != PeerState.DISCONNECTED && peer.Address.Host == receivedAddress.Host && peer.Address.Port == receivedAddress.Port && peer.SessionID == command.SessionID)
			{
				return -1;
			}
		}
		Peer peer2 = Array.Find(Peers, (Peer peer3) => peer3.State == PeerState.DISCONNECTED);
		if (peer2 == null)
		{
			return -1;
		}
		if (num > ChannelLimit)
		{
			num = ChannelLimit;
		}
		peer2.ResetChannels();
		peer2.ChannelCount = num;
		peer2.State = PeerState.ACKNOWLEDGING_CONNECT;
		peer2.SessionID = command.SessionID;
		peer2.Address = receivedAddress;
		peer2.OutgoingPeerID = command.OutgoingPeerID;
		peer2.IncomingBandwidth = command.IncomingBandwidth;
		peer2.OutgoingBandwidth = command.OutgoingBandwidth;
		peer2.PacketThrottleInterval = command.PacketThrottleInterval;
		peer2.PacketThrottleAcceleration = command.PacketThrottleAcceleration;
		peer2.PacketThrottleDeceleration = command.PacketThrottleDeceleration;
		peer2.MTU = Utils.Clamp(command.MTU, 576, 4096);
		if (OutgoingBandwidth == 0 && peer2.IncomingBandwidth == 0)
		{
			peer2.WindowSize = 32768u;
		}
		else if (OutgoingBandwidth == 0 || peer2.IncomingBandwidth == 0)
		{
			peer2.WindowSize = Math.Max(OutgoingBandwidth, peer2.IncomingBandwidth) / 65536 * 4096;
		}
		else
		{
			peer2.WindowSize = Math.Min(OutgoingBandwidth, peer2.IncomingBandwidth) / 65536 * 4096;
		}
		peer2.WindowSize = Utils.Clamp(peer2.WindowSize, 4096u, 32768u);
		uint num2 = ((IncomingBandwidth == 0) ? 32768u : (IncomingBandwidth / 65536 * 4096));
		if (num2 > command.WindowSize)
		{
			num2 = command.WindowSize;
		}
		num2 = Utils.Clamp(num2, 4096u, 32768u);
		Protocol.VerifyConnect command2 = new Protocol.VerifyConnect
		{
			Flags = ProtocolFlag.ACKNOWLEDGE,
			ChannelID = byte.MaxValue,
			OutgoingPeerID = peer2.IncomingPeerID,
			MTU = peer2.MTU,
			WindowSize = num2,
			ChannelCount = num,
			IncomingBandwidth = IncomingBandwidth,
			OutgoingBandwidth = OutgoingBandwidth,
			PacketThrottleInterval = peer2.PacketThrottleInterval,
			PacketThrottleAcceleration = peer2.PacketThrottleAcceleration,
			PacketThrottleDeceleration = peer2.PacketThrottleDeceleration
		};
		peer2.QueueOutgoingCommand(command2, null, 0u, 0);
		result = peer2;
		return 0;
	}

	private int HandleSendReliable(Peer peer, Protocol.Send.Reliable command, Buffer buffer)
	{
		if (command.ChannelID >= peer.ChannelCount)
		{
			return -1;
		}
		if (peer.State != PeerState.CONNECTED && peer.State != PeerState.DISCONNECT_LATER)
		{
			return -1;
		}
		if (command.DataLength > buffer.BytesLeft)
		{
			return -1;
		}
		Packet packet = new Packet(command.DataLength, PacketFlags.RELIABLE);
		buffer.ReadBytes(packet.Data, 0u, command.DataLength);
		if (peer.QueueIncomingCommand(command, packet, 0u) == null)
		{
			return -1;
		}
		return 0;
	}

	private int HandleSendUnsequenced(Peer peer, Protocol.Send.Unsequenced command, Buffer buffer)
	{
		if (command.ChannelID >= peer.ChannelCount)
		{
			return -1;
		}
		if (peer.State != PeerState.CONNECTED && peer.State != PeerState.DISCONNECT_LATER)
		{
			return -1;
		}
		if (command.DataLength > buffer.BytesLeft)
		{
			return -1;
		}
		uint num = command.UnsequencedGroup;
		uint num2 = num % 1024;
		if (num < peer.IncomingUnsequencedGroup)
		{
			num += 65536;
		}
		if (num >= (uint)(peer.IncomingUnsequencedGroup + 32768))
		{
			return 0;
		}
		num &= 0xFFFF;
		if (num - num2 != peer.IncomingUnsequencedGroup)
		{
			peer.IncomingUnsequencedGroup = (ushort)(num - num2);
			peer.UnsequencedWindow.SetAll(value: false);
		}
		else if (peer.UnsequencedWindow[(int)num2])
		{
			return 0;
		}
		Packet packet = new Packet(command.DataLength, PacketFlags.UNSEQUENCED);
		buffer.ReadBytes(packet.Data, 0u, command.DataLength);
		if (peer.QueueIncomingCommand(command, packet, 0u) == null)
		{
			return -1;
		}
		peer.UnsequencedWindow[(int)num2] = true;
		return 0;
	}

	private int HandleSendUnreliable(Peer peer, Protocol.Send.Unreliable command, Buffer buffer)
	{
		if (command.ChannelID >= peer.ChannelCount)
		{
			return -1;
		}
		if (peer.State != PeerState.CONNECTED && peer.State != PeerState.DISCONNECT_LATER)
		{
			return -1;
		}
		if (command.DataLength > buffer.BytesLeft)
		{
			return -1;
		}
		Packet packet = new Packet(command.DataLength, PacketFlags.NONE);
		buffer.ReadBytes(packet.Data, 0u, packet.DataLength);
		if (peer.QueueIncomingCommand(command, packet, 0u) == null)
		{
			return -1;
		}
		return 0;
	}

	private int HandleSendFragment(Peer peer, Protocol.Send.Fragment command, Buffer buffer)
	{
		if (command.ChannelID >= peer.ChannelCount)
		{
			return -1;
		}
		if (peer.State != PeerState.CONNECTED && peer.State != PeerState.DISCONNECT_LATER)
		{
			return -1;
		}
		if (command.DataLength > buffer.BytesLeft)
		{
			return -1;
		}
		uint num = command.DataLength;
		Channel channel = peer.Channels[command.ChannelID];
		uint startSequenceNumber = command.StartSequenceNumber;
		ushort num2 = (ushort)(startSequenceNumber / 4096);
		ushort num3 = (ushort)(channel.IncomingReliableSequenceNumber / 4096);
		if (startSequenceNumber < channel.IncomingReliableSequenceNumber)
		{
			num2 += 16;
		}
		if (num2 < num3 || num2 >= num3 + 8 - 1)
		{
			return 0;
		}
		uint fragmentNumber = command.FragmentNumber;
		uint fragmentCount = command.FragmentCount;
		uint fragmentOffset = command.FragmentOffset;
		uint totalLength = command.TotalLength;
		if (fragmentOffset >= totalLength || fragmentOffset + num > totalLength || fragmentNumber >= fragmentCount)
		{
			return -1;
		}
		IncomingCommand incomingCommand = null;
		for (LList<IncomingCommand>.Node prev = channel.IncomingReliableCommands.End.Prev; prev != channel.IncomingReliableCommands.End; prev = prev.Prev)
		{
			IncomingCommand value = prev.Value;
			if (startSequenceNumber >= channel.IncomingReliableSequenceNumber)
			{
				if (value.ReliableSequenceNumber < channel.IncomingReliableSequenceNumber)
				{
					continue;
				}
			}
			else if (value.ReliableSequenceNumber >= channel.IncomingReliableSequenceNumber)
			{
				break;
			}
			if (value.ReliableSequenceNumber <= startSequenceNumber)
			{
				if (value.ReliableSequenceNumber < startSequenceNumber)
				{
					break;
				}
				if (!(value.Command is Protocol.Send.Fragment) || totalLength != value.Packet.DataLength || fragmentCount != value.FragmentCount)
				{
					return -1;
				}
				incomingCommand = value;
				break;
			}
		}
		if (incomingCommand == null)
		{
			Packet packet = new Packet(totalLength, PacketFlags.RELIABLE);
			command.ReliableSequenceNumber = (ushort)startSequenceNumber;
			command.StartSequenceNumber = (ushort)startSequenceNumber;
			command.DataLength = (ushort)num;
			command.FragmentNumber = fragmentNumber;
			command.FragmentCount = fragmentCount;
			command.FragmentOffset = fragmentOffset;
			command.TotalLength = totalLength;
			incomingCommand = peer.QueueIncomingCommand(command, packet, fragmentCount);
		}
		if (!incomingCommand.Fragments[(int)fragmentNumber])
		{
			incomingCommand.FragmentsRemaining--;
			incomingCommand.Fragments[(int)fragmentNumber] = true;
			if (fragmentOffset + num > incomingCommand.Packet.DataLength)
			{
				num = incomingCommand.Packet.DataLength - fragmentOffset;
			}
			buffer.ReadBytes(incomingCommand.Packet.Data, fragmentOffset, num);
			if (incomingCommand.FragmentsRemaining == 0)
			{
				peer.DispatchIncomingReliableCommands(channel);
			}
		}
		return 0;
	}

	private int HandleBandwidthLimit(Peer peer, Protocol.BandwidthLimit command)
	{
		peer.IncomingBandwidth = command.IncomingBandwidth;
		peer.OutgoingBandwidth = command.OutgoingBandwidth;
		if (peer.IncomingBandwidth == 0 && OutgoingBandwidth == 0)
		{
			peer.WindowSize = 32768u;
		}
		else
		{
			peer.WindowSize = Math.Min(peer.IncomingBandwidth, OutgoingBandwidth) / 65536 * 4096;
		}
		peer.WindowSize = Utils.Clamp(peer.WindowSize, 4096u, 32768u);
		return 0;
	}

	private int HandleThrottleConfigure(Peer peer, Protocol.ThrottleConfigure command)
	{
		peer.PacketThrottleInterval = command.PacketThrottleInterval;
		peer.PacketThrottleAcceleration = command.PacketThrottleAcceleration;
		peer.PacketThrottleDeceleration = command.PacketThrottleDeceleration;
		return 0;
	}

	private int HandleDisconnect(Peer peer, Protocol.Disconnect command)
	{
		if (peer.State == PeerState.ZOMBIE || peer.State == PeerState.ACKNOWLEDGING_DISCONNECT)
		{
			return 0;
		}
		peer.ResetQueues();
		if (peer.State == PeerState.CONNECTION_SUCCEEDED || peer.State == PeerState.DISCONNECTING)
		{
			DispatchState(peer, PeerState.ZOMBIE);
		}
		else if (peer.State != PeerState.CONNECTED && peer.State != PeerState.DISCONNECT_LATER)
		{
			if (peer.State == PeerState.CONNECTION_PENDING)
			{
				RecalculateBandwidthLimits = true;
			}
			peer.Reset();
		}
		else if (command.Flags.HasFlag(ProtocolFlag.ACKNOWLEDGE))
		{
			peer.State = PeerState.ACKNOWLEDGING_DISCONNECT;
		}
		else
		{
			DispatchState(peer, PeerState.ZOMBIE);
		}
		peer.DisconnectData = command.Data;
		return 0;
	}

	private int HandleAcknowledge(Event evnt, Peer peer, Protocol.Acknowledge command)
	{
		uint receivedSentTime = command.ReceivedSentTime;
		receivedSentTime |= ServiceTime & 0xFFFF0000u;
		if ((receivedSentTime & 0x8000) > (ServiceTime & 0x8000))
		{
			receivedSentTime -= 65536;
		}
		if (Utils.TimeLess(ServiceTime, receivedSentTime))
		{
			return 0;
		}
		peer.LastReceiveTime = ServiceTime;
		peer.EarliestTimeout = 0u;
		uint num = Utils.TimeDiff(ServiceTime, receivedSentTime);
		peer.Throttle(num);
		peer.RoundTripTimeVariance -= peer.RoundTripTimeVariance / 4;
		if (num >= peer.RoundTripTime)
		{
			peer.RoundTripTime += (num - peer.RoundTripTime) / 8;
			peer.RoundTripTimeVariance += (num - peer.RoundTripTime) / 4;
		}
		else
		{
			peer.RoundTripTime -= (peer.RoundTripTime - num) / 8;
			peer.RoundTripTimeVariance += (peer.RoundTripTime - num) / 4;
		}
		if (peer.RoundTripTime < peer.LowestRoundTripTime)
		{
			peer.LowestRoundTripTime = peer.RoundTripTime;
		}
		if (peer.RoundTripTimeVariance > peer.HighestRoundTripTimeVariance)
		{
			peer.HighestRoundTripTimeVariance = peer.RoundTripTimeVariance;
		}
		if (peer.PacketThrottleEpoch == 0 || Utils.TimeDiff(ServiceTime, peer.PacketThrottleEpoch) >= peer.PacketThrottleInterval)
		{
			peer.LastRoundTripTime = peer.LowestRoundTripTime;
			peer.LastRoundTripTimeVariance = peer.HighestRoundTripTimeVariance;
			peer.LowestRoundTripTime = peer.RoundTripTime;
			peer.HighestRoundTripTimeVariance = peer.RoundTripTimeVariance;
			peer.PacketThrottleEpoch = ServiceTime;
		}
		uint receivedReliableSequenceNumber = command.ReceivedReliableSequenceNumber;
		ProtocolCommand protocolCommand = RemoveSentReliableCommand(peer, (ushort)receivedReliableSequenceNumber, command.ChannelID);
		switch (peer.State)
		{
		case PeerState.ACKNOWLEDGING_CONNECT:
			if (protocolCommand != ProtocolCommand.VERIFY_CONNECT)
			{
				return -1;
			}
			NotifyConnect(peer, evnt);
			break;
		case PeerState.DISCONNECTING:
			if (protocolCommand != ProtocolCommand.DISCONNECT)
			{
				return -1;
			}
			NotifyDisconnect(peer, evnt);
			break;
		case PeerState.DISCONNECT_LATER:
			if (peer.OutgoingReliableCommands.Empty && peer.OutgoingUnreliableCommands.Empty && peer.SentReliableCommands.Empty)
			{
				peer.Disconnect(peer.DisconnectData);
			}
			break;
		}
		return 0;
	}

	private int HandleVerifyConnect(Event evnt, Peer peer, Protocol.VerifyConnect command)
	{
		if (peer.State != PeerState.CONNECTING)
		{
			return 0;
		}
		uint channelCount = command.ChannelCount;
		if (channelCount < 1 || channelCount > 255 || command.PacketThrottleInterval != peer.PacketThrottleInterval || command.PacketThrottleAcceleration != peer.PacketThrottleAcceleration || command.PacketThrottleDeceleration != peer.PacketThrottleDeceleration)
		{
			DispatchState(peer, PeerState.ZOMBIE);
			return -1;
		}
		RemoveSentReliableCommand(peer, 1, byte.MaxValue);
		if (channelCount < peer.ChannelCount)
		{
			peer.ChannelCount = channelCount;
		}
		peer.OutgoingPeerID = command.OutgoingPeerID;
		ushort num = Utils.Clamp(command.MTU, 576, 4096);
		if (num < peer.MTU)
		{
			peer.MTU = num;
		}
		uint num2 = Utils.Clamp(command.WindowSize, 4096u, 32768u);
		if (num2 < peer.WindowSize)
		{
			peer.WindowSize = num2;
		}
		peer.IncomingBandwidth = command.IncomingBandwidth;
		peer.OutgoingBandwidth = command.OutgoingBandwidth;
		NotifyConnect(peer, evnt);
		return 0;
	}

	private int HandleIncomingCommands(Event evnt, Address receivedAddress, Buffer buffer)
	{
		uint dataLength = buffer.DataLength;
		ProtocolHeader protocolHeader = ProtocolHeader.Create(buffer, Version);
		if (protocolHeader == null)
		{
			return 0;
		}
		ushort peerID = protocolHeader.PeerID;
		Peer result = null;
		if (peerID != Version.MaxPeerID)
		{
			if (peerID > PeerCount)
			{
				return 0;
			}
			result = Peers[peerID];
			if (result.State == PeerState.DISCONNECTED || result.State == PeerState.ZOMBIE)
			{
				return 0;
			}
			if ((receivedAddress.Host != result.Address.Host || receivedAddress.Port != result.Address.Port) && result.Address.Host != uint.MaxValue)
			{
				return 0;
			}
			if (protocolHeader.SessionID != result.SessionID)
			{
				return 0;
			}
			result.Address = receivedAddress;
			result.IncomingDataTotal += dataLength;
		}
		while (buffer.BytesLeft != 0)
		{
			Protocol protocol = Protocol.Create(buffer, Version);
			if (protocol == null || protocol is Protocol.None || (result == null && !(protocol is Protocol.Connect)))
			{
				break;
			}
			Protocol protocol2 = protocol;
			Protocol protocol3 = protocol2;
			if ((protocol3 is Protocol.Acknowledge command) ? ((byte)HandleAcknowledge(evnt, result, command) != 0) : ((protocol3 is Protocol.Connect command2) ? ((byte)HandleConnect(receivedAddress, ref result, command2) != 0) : ((protocol3 is Protocol.VerifyConnect command3) ? ((byte)HandleVerifyConnect(evnt, result, command3) != 0) : ((protocol3 is Protocol.Disconnect command4) ? ((byte)HandleDisconnect(result, command4) != 0) : (!(protocol3 is Protocol.Ping) && ((protocol3 is Protocol.Send.Reliable command5) ? ((byte)HandleSendReliable(result, command5, buffer) != 0) : ((protocol3 is Protocol.Send.Unreliable command6) ? ((byte)HandleSendUnreliable(result, command6, buffer) != 0) : ((protocol3 is Protocol.Send.Unsequenced command7) ? ((byte)HandleSendUnsequenced(result, command7, buffer) != 0) : ((protocol3 is Protocol.Send.Fragment command8) ? ((byte)HandleSendFragment(result, command8, buffer) != 0) : ((protocol3 is Protocol.BandwidthLimit command9) ? ((byte)HandleBandwidthLimit(result, command9) != 0) : ((!(protocol3 is Protocol.ThrottleConfigure command10)) ? true : ((byte)HandleThrottleConfigure(result, command10) != 0))))))))))))
			{
				break;
			}
			if (result == null || !protocol.Flags.HasFlag(ProtocolFlag.ACKNOWLEDGE))
			{
				continue;
			}
			ushort? timeSent = protocolHeader.TimeSent;
			if (!timeSent.HasValue)
			{
				break;
			}
			ushort valueOrDefault = timeSent.GetValueOrDefault();
			if (1 == 0)
			{
				break;
			}
			switch (result.State)
			{
			case PeerState.ACKNOWLEDGING_DISCONNECT:
				if (protocol is Protocol.Disconnect)
				{
					result.QueueAcknowledgement(protocol, valueOrDefault);
				}
				break;
			default:
				result.QueueAcknowledgement(protocol, valueOrDefault);
				break;
			case PeerState.ACKNOWLEDGING_CONNECT:
			case PeerState.DISCONNECTING:
				break;
			}
		}
		if (evnt != null && evnt.Type != EventType.NONE)
		{
			return 1;
		}
		return 0;
	}

	private int ReceiveIncomingCommands(Event evnt)
	{
		Buffer buffer = new Buffer(4096u);
		while (true)
		{
			Address receivedAddres = new Address(0u, 0);
			int num = Socket.ReceiveFrom(ref receivedAddres, buffer);
			if (num < 0)
			{
				return -1;
			}
			if (num == 0)
			{
				break;
			}
			buffer.DataLength = (uint)num;
			TotalReceivedData += (uint)num;
			TotalReceivedPackets++;
			switch (HandleIncomingCommands(evnt, receivedAddres, buffer))
			{
			case 1:
				return 1;
			case -1:
				return -1;
			}
		}
		return 0;
	}

	private void SendAcknowledgements(Peer peer, Buffer buffer, ref bool continueSending)
	{
		LList<Acknowledgement>.Node node = peer.Acknowledgements.Begin;
		while (node != peer.Acknowledgements.End)
		{
			if (8 > buffer.BytesLeft)
			{
				continueSending = true;
				break;
			}
			Acknowledgement value = node.Value;
			node = node.Next;
			Protocol.Acknowledge acknowledge = new Protocol.Acknowledge
			{
				ChannelID = value.Command.ChannelID,
				ReceivedReliableSequenceNumber = value.Command.ReliableSequenceNumber,
				ReceivedSentTime = (ushort)value.SentTime
			};
			acknowledge.Write(buffer, Version);
			if (value.Command is Protocol.Disconnect)
			{
				DispatchState(peer, PeerState.ZOMBIE);
			}
			value.Node.Remove();
		}
	}

	private void SendUnreliableOutgoingCommands(Peer peer, Buffer buffer, ref bool continueSending)
	{
		LList<OutgoingCommand>.Node node = peer.OutgoingUnreliableCommands.Begin;
		while (node != peer.OutgoingUnreliableCommands.End)
		{
			OutgoingCommand value = node.Value;
			uint num = value.Command.Size;
			if (value.Packet != null)
			{
				num += value.Packet.DataLength;
			}
			if (num > buffer.BytesLeft)
			{
				continueSending = true;
				break;
			}
			node = node.Next;
			if (value.Packet != null)
			{
				peer.PacketThrottleCounter += 7u;
				peer.PacketThrottleCounter %= 32u;
				if (peer.PacketThrottleCounter > peer.PacketThrottle)
				{
					value.Node.Remove();
					continue;
				}
			}
			value.Command.Write(buffer, Version);
			value.Node.Remove();
			if (value.Packet != null)
			{
				buffer.WriteBytes(value.Packet.Data);
				peer.SentUnreliableCommands.End.Insert(value.Node);
			}
		}
		if (peer.State == PeerState.DISCONNECT_LATER && peer.OutgoingReliableCommands.Empty && peer.OutgoingUnreliableCommands.Empty && peer.SentReliableCommands.Empty)
		{
			peer.Disconnect(peer.DisconnectData);
		}
	}

	private int CheckTimeouts(Peer peer, Event evnt)
	{
		LList<OutgoingCommand>.Node node = peer.SentReliableCommands.Begin;
		LList<OutgoingCommand>.Node begin = peer.OutgoingReliableCommands.Begin;
		while (node != peer.SentReliableCommands.End)
		{
			OutgoingCommand value = node.Value;
			node = node.Next;
			if (Utils.TimeDiff(ServiceTime, value.SentTime) >= value.RoundTripTimeout)
			{
				if (peer.EarliestTimeout == 0 || Utils.TimeLess(value.SentTime, peer.EarliestTimeout))
				{
					peer.EarliestTimeout = value.SentTime;
				}
				if (peer.EarliestTimeout != 0 && (Utils.TimeDiff(ServiceTime, peer.EarliestTimeout) >= 30000 || (value.RoundTripTimeout >= value.RoundTripTimeoutLimit && Utils.TimeDiff(ServiceTime, peer.EarliestTimeout) >= 5000)))
				{
					NotifyDisconnect(peer, evnt);
					return 1;
				}
				if (value.Packet != null)
				{
					peer.ReliableDataInTransit -= value.FragmentLength;
				}
				peer.PacketsLost++;
				value.RoundTripTimeout *= 2u;
				begin.Insert(value.Node.Remove());
				if (node == peer.SentReliableCommands.Begin && !peer.SentReliableCommands.Empty)
				{
					value = node.Value;
					peer.NextTimeout = value.SentTime + value.RoundTripTimeout;
				}
			}
		}
		return 0;
	}

	private void SendReliableOutgoingCommands(Peer peer, Buffer buffer, ref bool continueSending, ref bool hasSentTime)
	{
		LList<OutgoingCommand>.Node node = peer.OutgoingReliableCommands.Begin;
		while (node != peer.OutgoingReliableCommands.End)
		{
			OutgoingCommand value = node.Value;
			Channel channel = ((value.Command.ChannelID < peer.ChannelCount) ? peer.Channels[value.Command.ChannelID] : null);
			ushort num = (ushort)(value.ReliableSequenceNumber / 4096);
			if (channel != null && value.SendAttempts < 1 && value.ReliableSequenceNumber % 4096 == 0 && (channel.ReliableWindows[(num + 16 - 1) % 16] >= 4096 || (channel.UsedReliableWindows & ((255 << (int)num) | (255 >>> 4096 - num))) != 0))
			{
				break;
			}
			uint size = value.Command.Size;
			if (size > buffer.BytesLeft)
			{
				continueSending = true;
				break;
			}
			if (value.Packet != null)
			{
				uint val = peer.PacketThrottle * peer.WindowSize / 32;
				if (peer.ReliableDataInTransit + value.FragmentLength > Math.Max(val, peer.MTU))
				{
					break;
				}
				if ((ushort)(size + value.FragmentLength) > (ushort)buffer.BytesLeft)
				{
					continueSending = true;
					break;
				}
			}
			node = node.Next;
			if (channel != null && value.SendAttempts < 1)
			{
				channel.UsedReliableWindows |= (ushort)(1 << (int)num);
				channel.ReliableWindows[num]++;
			}
			value.SendAttempts++;
			if (value.RoundTripTimeout == 0)
			{
				value.RoundTripTimeout = peer.RoundTripTime + 4 * peer.RoundTripTimeVariance;
				value.RoundTripTimeoutLimit = 32 * value.RoundTripTimeout;
			}
			if (peer.SentReliableCommands.Empty)
			{
				peer.NextTimeout = ServiceTime + value.RoundTripTimeout;
			}
			peer.SentReliableCommands.End.Insert(value.Node.Remove());
			value.SentTime = ServiceTime;
			Protocol command = value.Command;
			hasSentTime = true;
			command.Write(buffer, Version);
			if (value.Packet != null)
			{
				buffer.WriteBytes(value.Packet.Data, value.FragmentOffset, value.FragmentLength);
				peer.ReliableDataInTransit += value.FragmentLength;
			}
			peer.PacketsSent++;
		}
	}

	private int SendOutgoingCommands(Event evnt, bool checkForTimeout)
	{
		Buffer buffer = new Buffer(4096u);
		bool continueSending = true;
		while (continueSending)
		{
			continueSending = false;
			Peer[] peers = Peers;
			foreach (Peer peer in peers)
			{
				if (peer.State == PeerState.DISCONNECTED || peer.State == PeerState.ZOMBIE)
				{
					continue;
				}
				bool hasSentTime = false;
				buffer.Position = Version.MaxHeaderSizeSend;
				buffer.DataLength = peer.MTU;
				if (!peer.Acknowledgements.Empty)
				{
					SendAcknowledgements(peer, buffer, ref continueSending);
				}
				if (checkForTimeout && !peer.SentReliableCommands.Empty && !Utils.TimeLess(ServiceTime, peer.NextTimeout) && CheckTimeouts(peer, evnt) == 1)
				{
					return 1;
				}
				if (!peer.OutgoingReliableCommands.Empty)
				{
					SendReliableOutgoingCommands(peer, buffer, ref continueSending, ref hasSentTime);
				}
				else if (peer.SentReliableCommands.Empty && Utils.TimeDiff(ServiceTime, peer.LastReceiveTime) >= 500 && 4 <= buffer.BytesLeft)
				{
					peer.Ping();
					SendReliableOutgoingCommands(peer, buffer, ref continueSending, ref hasSentTime);
				}
				if (!peer.OutgoingUnreliableCommands.Empty)
				{
					SendUnreliableOutgoingCommands(peer, buffer, ref continueSending);
				}
				if (buffer.Position <= Version.MaxHeaderSizeSend)
				{
					continue;
				}
				if (peer.PacketLossEpoch == 0)
				{
					peer.PacketLossEpoch = ServiceTime;
				}
				else if (Utils.TimeDiff(ServiceTime, peer.PacketLossEpoch) >= Version.PacketLossInterval && peer.PacketsSent != 0)
				{
					uint num = peer.PacketsLost * 65536 / peer.PacketsSent;
					peer.PacketLossVariance -= peer.PacketLossVariance / 4;
					if (num >= peer.PacketLoss)
					{
						peer.PacketLoss += (num - peer.PacketLoss) / 8;
						peer.PacketLossVariance += (num - peer.PacketLoss) / 4;
					}
					else
					{
						peer.PacketLoss -= (peer.PacketLoss - num) / 8;
						peer.PacketLossVariance += (peer.PacketLoss - num) / 4;
					}
					peer.PacketLossEpoch = ServiceTime;
					peer.PacketsSent = 0u;
					peer.PacketsLost = 0u;
				}
				uint num2 = buffer.Position;
				uint num3 = 0u;
				ProtocolHeader protocolHeader = new ProtocolHeader
				{
					SessionID = peer.SessionID,
					PeerID = peer.OutgoingPeerID
				};
				if (hasSentTime)
				{
					protocolHeader.TimeSent = (ushort)ServiceTime;
				}
				else
				{
					protocolHeader.TimeSent = null;
					num3 += 2;
					num2 -= 2;
				}
				buffer.Position = num3;
				protocolHeader.Write(buffer, Version);
				peer.LastSendTime = ServiceTime;
				int num4 = Socket.SendTo(peer.Address, buffer.Data, num3, num2);
				RemoveSentUnreliableCommands(peer);
				if (num4 < 0)
				{
					return -1;
				}
				TotalSentData += (uint)num4;
				TotalSentPackets++;
			}
		}
		return 0;
	}

	public void Flush()
	{
		ServiceTime = GetTime();
		SendOutgoingCommands(null, checkForTimeout: false);
	}

	public int CheckEvents(Event evnt)
	{
		if (evnt != null)
		{
			evnt.Type = EventType.NONE;
			evnt.Peer = null;
			evnt.Packet = null;
			return DispatchIncomingCommands(evnt);
		}
		return -1;
	}

	public int HostService(Event evnt, uint timeout)
	{
		if (evnt != null)
		{
			evnt.Type = EventType.NONE;
			evnt.Peer = null;
			evnt.Packet = null;
			switch (DispatchIncomingCommands(evnt))
			{
			case 1:
				return 1;
			case -1:
				return -1;
			}
		}
		ServiceTime = GetTime();
		timeout += ServiceTime;
		while (true)
		{
			if (Utils.TimeDiff(ServiceTime, BandwidthThrottleEpoch) >= Version.BandwidthThrottleInterval)
			{
				BandwidthThrottle();
			}
			switch (SendOutgoingCommands(evnt, checkForTimeout: true))
			{
			case 1:
				return 1;
			case -1:
				return -1;
			}
			switch (ReceiveIncomingCommands(evnt))
			{
			case 1:
				return 1;
			case -1:
				return -1;
			}
			switch (SendOutgoingCommands(evnt, checkForTimeout: true))
			{
			case 1:
				return 1;
			case -1:
				return -1;
			}
			if (evnt != null)
			{
				switch (DispatchIncomingCommands(evnt))
				{
				case 1:
					return 1;
				case -1:
					return -1;
				}
			}
			ServiceTime = GetTime();
			if (!Utils.TimeLess(ServiceTime, timeout))
			{
				return 0;
			}
			bool condition = true;
			if (Socket.WaitReceive(ref condition, Utils.TimeDiff(timeout, ServiceTime)) != 0)
			{
				return -1;
			}
			ServiceTime = GetTime();
			if (!condition)
			{
				return 0;
			}
		}
	}
}
