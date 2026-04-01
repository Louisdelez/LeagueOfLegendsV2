using System;
using System.Collections;

namespace LENet;

public sealed class Peer : LList<Peer>.Element
{
	public const ushort DEFAULT_ROUND_TRIP_TIME = 500;

	public const byte DEFAULT_PACKET_THROTTLE = 32;

	public const byte PACKET_THROTTLE_SCALE = 32;

	public const byte PACKET_THROTTLE_COUNTER = 7;

	public const byte PACKET_THROTTLE_ACCELERATION = 2;

	public const byte PACKET_THROTTLE_DECELERATION = 2;

	public const ushort PACKET_THROTTLE_INTERVAL = 5000;

	public const uint PACKET_LOSS_SCALE = 65536u;

	public const uint WINDOW_SIZE_SCALE = 65536u;

	public const byte TIMEOUT_LIMIT = 32;

	public const ushort TIMEOUT_MINIMUM = 5000;

	public const ushort TIMEOUT_MAXIMUM = 30000;

	public const ushort PING_INTERVAL = 500;

	public const byte UNSEQUENCED_WINDOWS = 64;

	public const ushort UNSEQUENCED_WINDOW_SIZE = 1024;

	public const byte FREE_UNSEQUENCED_WINDOWS = 32;

	public const byte RELIABLE_WINDOWS = 16;

	public const ushort RELIABLE_WINDOW_SIZE = 4096;

	public const byte FREE_RELIABLE_WINDOWS = 8;

	public const uint FREE_RELIABLE_WINDOWS_MASK = 255u;

	public Host Host { get; }

	public ushort OutgoingPeerID { get; set; }

	public ushort IncomingPeerID { get; set; }

	public uint SessionID { get; set; }

	public Address Address { get; set; }

	public object UserData { get; set; }

	public PeerState State { get; set; }

	public Channel[] Channels { get; }

	public uint ChannelCount { get; set; }

	public uint IncomingBandwidth { get; set; }

	public uint OutgoingBandwidth { get; set; }

	public uint IncomingBandwidthThrottleEpoch { get; set; }

	public uint OutgoingBandwidthThrottleEpoch { get; set; }

	public uint IncomingDataTotal { get; set; }

	public uint OutgoingDataTotal { get; set; }

	public uint LastSendTime { get; set; }

	public uint LastReceiveTime { get; set; }

	public uint NextTimeout { get; set; }

	public uint EarliestTimeout { get; set; }

	public uint PacketLossEpoch { get; set; }

	public uint PacketsSent { get; set; }

	public uint PacketsLost { get; set; }

	public uint PacketLoss { get; set; }

	public uint PacketLossVariance { get; set; }

	public uint PacketThrottle { get; set; }

	public uint PacketThrottleLimit { get; set; }

	public uint PacketThrottleCounter { get; set; }

	public uint PacketThrottleEpoch { get; set; }

	public uint PacketThrottleAcceleration { get; set; }

	public uint PacketThrottleDeceleration { get; set; }

	public uint PacketThrottleInterval { get; set; }

	public uint LastRoundTripTime { get; set; }

	public uint LowestRoundTripTime { get; set; }

	public uint LastRoundTripTimeVariance { get; set; }

	public uint HighestRoundTripTimeVariance { get; set; }

	public uint RoundTripTime { get; set; }

	public uint RoundTripTimeVariance { get; set; }

	public ushort MTU { get; set; }

	public uint WindowSize { get; set; }

	public uint ReliableDataInTransit { get; set; }

	public ushort OutgoingReliableSequenceNumber { get; set; }

	public LList<Acknowledgement> Acknowledgements { get; } = new LList<Acknowledgement>();

	public LList<OutgoingCommand> SentReliableCommands { get; } = new LList<OutgoingCommand>();

	public LList<OutgoingCommand> SentUnreliableCommands { get; } = new LList<OutgoingCommand>();

	public LList<OutgoingCommand> OutgoingReliableCommands { get; } = new LList<OutgoingCommand>();

	public LList<OutgoingCommand> OutgoingUnreliableCommands { get; } = new LList<OutgoingCommand>();

	public LList<IncomingCommand> DispatchedCommands { get; } = new LList<IncomingCommand>();

	public bool NeedsDispatch { get; set; }

	public ushort IncomingUnsequencedGroup { get; set; }

	public ushort OutgoingUnsequencedGroup { get; set; }

	public BitArray UnsequencedWindow { get; } = new BitArray(1024);

	public uint DisconnectData { get; set; }

	public Peer(Host host, ushort id)
	{
		Host = host;
		IncomingPeerID = id;
		Channels = new Channel[Host.ChannelLimit];
		for (int i = 0; i < Channels.Length; i++)
		{
			Channels[i] = new Channel();
		}
		Reset();
	}

	public void ThrottleConfigure(uint interval, uint acceleration, uint deceleration)
	{
		PacketThrottleInterval = interval;
		PacketThrottleAcceleration = acceleration;
		PacketThrottleDeceleration = deceleration;
		Protocol.ThrottleConfigure command = new Protocol.ThrottleConfigure
		{
			ChannelID = byte.MaxValue,
			Flags = ProtocolFlag.ACKNOWLEDGE,
			PacketThrottleInterval = interval,
			PacketThrottleAcceleration = acceleration,
			PacketThrottleDeceleration = deceleration
		};
		QueueOutgoingCommand(command, null, 0u, 0);
	}

	public int Throttle(uint rtt)
	{
		if (LastRoundTripTime <= LastRoundTripTimeVariance)
		{
			PacketThrottle = PacketThrottleLimit;
		}
		else
		{
			if (rtt < LastRoundTripTime)
			{
				PacketThrottle += PacketThrottleAcceleration;
				if (PacketThrottle > PacketThrottleLimit)
				{
					PacketThrottle = PacketThrottleLimit;
				}
				return 1;
			}
			if (rtt > LastRoundTripTime + 2 * LastRoundTripTimeVariance)
			{
				if (PacketThrottle > PacketThrottleDeceleration)
				{
					PacketThrottle -= PacketThrottleDeceleration;
				}
				else
				{
					PacketThrottle = 0u;
				}
				return -1;
			}
		}
		return 0;
	}

	public int Send(byte channelID, Packet packet)
	{
		if (State != PeerState.CONNECTED || channelID >= ChannelCount)
		{
			return -1;
		}
		Channel channel = Channels[channelID];
		uint num = MTU - Host.Version.MaxHeaderSizeSend - 24;
		if (packet.DataLength > num)
		{
			ushort startSequenceNumber = (ushort)(channel.OutgoingReliableSequenceNumber + 1);
			uint fragmentCount = (packet.DataLength + num - 1) / num;
			uint num2 = 0u;
			uint num3 = 0u;
			while (num3 < packet.DataLength)
			{
				if (packet.DataLength - num3 < num)
				{
					num = packet.DataLength - num3;
				}
				OutgoingCommand outgoingCommand = new OutgoingCommand
				{
					FragmentOffset = num3,
					FragmentLength = (ushort)num,
					Packet = packet,
					Command = new Protocol.Send.Fragment
					{
						Flags = ProtocolFlag.ACKNOWLEDGE,
						ChannelID = channelID,
						StartSequenceNumber = startSequenceNumber,
						DataLength = (ushort)num,
						FragmentCount = fragmentCount,
						FragmentNumber = num2,
						TotalLength = packet.DataLength,
						FragmentOffset = num3
					}
				};
				SetupOutgoingCommand(outgoingCommand);
				num3 += num;
				num2++;
			}
			return 0;
		}
		Protocol command = (packet.Flags.HasFlag(PacketFlags.RELIABLE) ? new Protocol.Send.Reliable
		{
			ChannelID = channelID,
			Flags = ProtocolFlag.ACKNOWLEDGE,
			DataLength = (ushort)packet.DataLength
		} : (packet.Flags.HasFlag(PacketFlags.UNSEQUENCED) ? new Protocol.Send.Unsequenced
		{
			ChannelID = channelID,
			Flags = ProtocolFlag.UNSEQUENCED,
			UnsequencedGroup = (ushort)(OutgoingUnsequencedGroup + 1),
			DataLength = (ushort)packet.DataLength
		} : (((uint)channel.OutgoingReliableSequenceNumber < 65535u) ? ((Protocol)new Protocol.Send.Unreliable
		{
			ChannelID = channelID,
			UnreliableSequenceNumber = (ushort)(channel.OutgoingUnreliableSequenceNumber + 1),
			DataLength = (ushort)packet.DataLength
		}) : ((Protocol)new Protocol.Send.Reliable
		{
			ChannelID = channelID,
			Flags = ProtocolFlag.ACKNOWLEDGE,
			DataLength = (ushort)packet.DataLength
		}))));
		if (QueueOutgoingCommand(command, packet, 0u, (ushort)packet.DataLength) == null)
		{
			return -1;
		}
		return 0;
	}

	public Packet Recieve(out byte ChannelID)
	{
		if (DispatchedCommands.Empty)
		{
			ChannelID = 0;
			return null;
		}
		IncomingCommand value = DispatchedCommands.Begin.Remove().Value;
		ChannelID = value.Command.ChannelID;
		return value.Packet;
	}

	public void ResetChannels()
	{
		if (ChannelCount != 0)
		{
			Channel[] channels = Channels;
			foreach (Channel channel in channels)
			{
				Array.Clear(channel.ReliableWindows, 0, channel.ReliableWindows.Length);
				channel.IncomingReliableCommands.Clear();
				channel.IncomingUnreliableCommands.Clear();
			}
			ChannelCount = 0u;
		}
	}

	public void ResetQueues()
	{
		if (NeedsDispatch)
		{
			Node.Remove();
			NeedsDispatch = false;
		}
		Acknowledgements.Clear();
		SentReliableCommands.Clear();
		SentUnreliableCommands.Clear();
		OutgoingReliableCommands.Clear();
		OutgoingUnreliableCommands.Clear();
		DispatchedCommands.Clear();
		ResetChannels();
	}

	public void Reset()
	{
		OutgoingPeerID = Host.Version.MaxPeerID;
		SessionID = 0u;
		State = PeerState.DISCONNECTED;
		IncomingBandwidth = 0u;
		OutgoingBandwidth = 0u;
		IncomingBandwidthThrottleEpoch = 0u;
		OutgoingBandwidthThrottleEpoch = 0u;
		IncomingDataTotal = 0u;
		OutgoingDataTotal = 0u;
		LastSendTime = 0u;
		LastReceiveTime = 0u;
		NextTimeout = 0u;
		EarliestTimeout = 0u;
		PacketLossEpoch = 0u;
		PacketsSent = 0u;
		PacketsLost = 0u;
		PacketLoss = 0u;
		PacketLossVariance = 0u;
		PacketThrottle = 32u;
		PacketThrottleLimit = 32u;
		PacketThrottleCounter = 0u;
		PacketThrottleEpoch = 0u;
		PacketThrottleAcceleration = 2u;
		PacketThrottleDeceleration = 2u;
		PacketThrottleInterval = 5000u;
		LastRoundTripTime = 500u;
		LowestRoundTripTime = 500u;
		LastRoundTripTimeVariance = 0u;
		HighestRoundTripTimeVariance = 0u;
		RoundTripTime = 500u;
		RoundTripTimeVariance = 0u;
		MTU = (ushort)Host.MTU;
		ReliableDataInTransit = 0u;
		OutgoingReliableSequenceNumber = 0;
		WindowSize = 32768u;
		IncomingUnsequencedGroup = 0;
		OutgoingUnsequencedGroup = 0;
		DisconnectData = 0u;
		UnsequencedWindow.SetAll(value: false);
		ResetQueues();
	}

	public void Ping()
	{
		if (State == PeerState.CONNECTED)
		{
			Protocol.Ping command = new Protocol.Ping
			{
				ChannelID = byte.MaxValue,
				Flags = ProtocolFlag.ACKNOWLEDGE
			};
			QueueOutgoingCommand(command, null, 0u, 0);
		}
	}

	public void DisconnectNow(uint data)
	{
		if (State != PeerState.DISCONNECTED)
		{
			if (State != PeerState.ZOMBIE && State != PeerState.DISCONNECTING)
			{
				ResetQueues();
				Protocol.Disconnect command = new Protocol.Disconnect
				{
					Flags = ProtocolFlag.UNSEQUENCED,
					ChannelID = byte.MaxValue,
					Data = data
				};
				QueueOutgoingCommand(command, null, 0u, 0);
				Host.Flush();
			}
			Reset();
		}
	}

	public void Disconnect(uint data)
	{
		if (State != PeerState.DISCONNECTING && State != PeerState.DISCONNECTED && State != PeerState.ACKNOWLEDGING_DISCONNECT && State != PeerState.ZOMBIE)
		{
			ResetQueues();
			Protocol.Disconnect disconnect = new Protocol.Disconnect
			{
				ChannelID = byte.MaxValue,
				Data = data
			};
			if (State == PeerState.CONNECTED || State == PeerState.DISCONNECT_LATER)
			{
				disconnect.Flags |= ProtocolFlag.ACKNOWLEDGE;
			}
			else
			{
				disconnect.Flags |= ProtocolFlag.UNSEQUENCED;
			}
			QueueOutgoingCommand(disconnect, null, 0u, 0);
			if (State == PeerState.CONNECTED || State == PeerState.DISCONNECT_LATER)
			{
				State = PeerState.DISCONNECTING;
				return;
			}
			Host.Flush();
			Reset();
		}
	}

	public void DisconnectLater(uint data)
	{
		if ((State == PeerState.CONNECTED || State == PeerState.DISCONNECT_LATER) && (!OutgoingReliableCommands.Empty || !OutgoingUnreliableCommands.Empty || !SentReliableCommands.Empty))
		{
			State = PeerState.DISCONNECT_LATER;
			DisconnectData = data;
		}
		else
		{
			Disconnect(data);
		}
	}

	public Acknowledgement QueueAcknowledgement(Protocol command, ushort sentTime)
	{
		if (command.ChannelID < ChannelCount)
		{
			Channel channel = Channels[command.ChannelID];
			ushort num = (ushort)(command.ReliableSequenceNumber / 4096);
			ushort num2 = (ushort)(channel.IncomingReliableSequenceNumber / 4096);
			if (command.ReliableSequenceNumber < channel.IncomingReliableSequenceNumber)
			{
				num += 16;
			}
			if (num >= num2 + 8 - 1 && num <= num2 + 8)
			{
				return null;
			}
		}
		Acknowledgement acknowledgement = new Acknowledgement
		{
			SentTime = sentTime,
			Command = command
		};
		OutgoingDataTotal += 8u;
		Acknowledgements.End.Insert(acknowledgement.Node);
		return acknowledgement;
	}

	public void SetupOutgoingCommand(OutgoingCommand outgoingCommand)
	{
		OutgoingDataTotal += (uint)(outgoingCommand.Command.Size + outgoingCommand.FragmentLength);
		if (outgoingCommand.Command.ChannelID == byte.MaxValue)
		{
			OutgoingReliableSequenceNumber++;
			outgoingCommand.ReliableSequenceNumber = OutgoingReliableSequenceNumber;
			outgoingCommand.UnreliableSequenceNumber = 0;
		}
		else
		{
			Channel channel = Channels[outgoingCommand.Command.ChannelID];
			if (outgoingCommand.Command.Flags.HasFlag(ProtocolFlag.ACKNOWLEDGE))
			{
				channel.OutgoingReliableSequenceNumber++;
				channel.OutgoingUnreliableSequenceNumber = 0;
				outgoingCommand.ReliableSequenceNumber = channel.OutgoingReliableSequenceNumber;
				outgoingCommand.UnreliableSequenceNumber = 0;
			}
			else if (outgoingCommand.Command.Flags.HasFlag(ProtocolFlag.UNSEQUENCED))
			{
				OutgoingUnsequencedGroup++;
				outgoingCommand.ReliableSequenceNumber = 0;
				outgoingCommand.UnreliableSequenceNumber = 0;
			}
			else
			{
				channel.OutgoingUnreliableSequenceNumber++;
				outgoingCommand.ReliableSequenceNumber = channel.OutgoingReliableSequenceNumber;
				outgoingCommand.UnreliableSequenceNumber = channel.OutgoingUnreliableSequenceNumber;
			}
		}
		outgoingCommand.SendAttempts = 0;
		outgoingCommand.SentTime = 0u;
		outgoingCommand.RoundTripTimeout = 0u;
		outgoingCommand.RoundTripTimeoutLimit = 0u;
		outgoingCommand.Command.ReliableSequenceNumber = outgoingCommand.ReliableSequenceNumber;
		if (outgoingCommand.Command.Flags.HasFlag(ProtocolFlag.ACKNOWLEDGE))
		{
			OutgoingReliableCommands.End.Insert(outgoingCommand.Node);
		}
		else
		{
			OutgoingUnreliableCommands.End.Insert(outgoingCommand.Node);
		}
	}

	public OutgoingCommand QueueOutgoingCommand(Protocol command, Packet packet, uint offset, ushort length)
	{
		OutgoingCommand outgoingCommand = new OutgoingCommand
		{
			Command = command,
			FragmentOffset = offset,
			FragmentLength = length,
			Packet = packet
		};
		SetupOutgoingCommand(outgoingCommand);
		return outgoingCommand;
	}

	public void DispatchIncomingUnreliableCommands(Channel channel)
	{
		LList<IncomingCommand>.Node node;
		for (node = channel.IncomingUnreliableCommands.Begin; node != channel.IncomingUnreliableCommands.End; node = node.Next)
		{
			IncomingCommand value = node.Value;
			if (value.Command is Protocol.Send.Unreliable)
			{
				if (value.ReliableSequenceNumber != channel.IncomingReliableSequenceNumber)
				{
					break;
				}
				channel.IncomingUnreliableSequenceNumber = value.UnreliableSequenceNumber;
			}
		}
		if (node != channel.IncomingUnreliableCommands.Begin)
		{
			DispatchedCommands.End.Move(channel.IncomingUnreliableCommands.Begin, node.Prev);
			if (!NeedsDispatch)
			{
				Host.DispatchQueue.End.Insert(Node);
				NeedsDispatch = true;
			}
		}
	}

	public void DispatchIncomingReliableCommands(Channel channel)
	{
		LList<IncomingCommand>.Node node;
		for (node = channel.IncomingReliableCommands.Begin; node != channel.IncomingReliableCommands.End; node = node.Next)
		{
			IncomingCommand value = node.Value;
			if (value.FragmentsRemaining != 0 || value.ReliableSequenceNumber != (ushort)(channel.IncomingReliableSequenceNumber + 1))
			{
				break;
			}
			channel.IncomingReliableSequenceNumber = value.ReliableSequenceNumber;
			if (value.FragmentCount != 0)
			{
				channel.IncomingReliableSequenceNumber += (ushort)(value.FragmentCount - 1);
			}
		}
		if (node != channel.IncomingReliableCommands.Begin)
		{
			channel.IncomingUnreliableSequenceNumber = 0;
			DispatchedCommands.End.Move(channel.IncomingReliableCommands.Begin, node.Prev);
			if (!NeedsDispatch)
			{
				Host.DispatchQueue.End.Insert(Node);
				NeedsDispatch = true;
			}
			DispatchIncomingUnreliableCommands(channel);
		}
	}

	public IncomingCommand QueueIncomingCommand(Protocol command, Packet packet, uint fragmentCount)
	{
		Channel channel = ((command.ChannelID == byte.MaxValue) ? null : Channels[command.ChannelID]);
		IncomingCommand result = ((fragmentCount != 0) ? null : new IncomingCommand());
		if (State == PeerState.DISCONNECT_LATER)
		{
			return result;
		}
		uint num = 0u;
		uint num2 = 0u;
		if (!(command is Protocol.Send.Unsequenced))
		{
			num2 = command.ReliableSequenceNumber;
			ushort num3 = (ushort)(num2 / 4096);
			ushort num4 = (ushort)(channel.IncomingReliableSequenceNumber / 4096);
			if (num2 < channel.IncomingReliableSequenceNumber)
			{
				num3 += 16;
			}
			if (num3 < num4 || num3 >= (long)(num4 + 8) - 1L)
			{
				return result;
			}
		}
		LList<IncomingCommand>.Node node;
		IncomingCommand value;
		if (!(command is Protocol.Send.Fragment) && !(command is Protocol.Send.Reliable))
		{
			if (!(command is Protocol.Send.Unreliable unreliable))
			{
				if (!(command is Protocol.Send.Unsequenced))
				{
					return result;
				}
				node = channel.IncomingUnreliableCommands.End;
			}
			else
			{
				num = unreliable.UnreliableSequenceNumber;
				if (num2 == channel.IncomingReliableSequenceNumber && num <= channel.IncomingUnreliableSequenceNumber)
				{
					return result;
				}
				for (node = channel.IncomingUnreliableCommands.End.Prev; node != channel.IncomingUnreliableCommands.End; node = node.Prev)
				{
					value = node.Value;
					if (!(value.Command is Protocol.Send.Unreliable))
					{
						continue;
					}
					if (num2 >= channel.IncomingReliableSequenceNumber)
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
					if (value.ReliableSequenceNumber < num2)
					{
						break;
					}
					if (value.ReliableSequenceNumber > num2 || value.UnreliableSequenceNumber > num)
					{
						continue;
					}
					if (value.UnreliableSequenceNumber < num)
					{
						break;
					}
					return result;
				}
			}
		}
		else
		{
			if (num2 == channel.IncomingReliableSequenceNumber)
			{
				return result;
			}
			for (node = channel.IncomingReliableCommands.End.Prev; node != channel.IncomingReliableCommands.End; node = node.Prev)
			{
				value = node.Value;
				if (num2 >= channel.IncomingReliableSequenceNumber)
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
				if (value.ReliableSequenceNumber <= num2)
				{
					if (value.ReliableSequenceNumber < num2)
					{
						break;
					}
					return result;
				}
			}
		}
		value = new IncomingCommand
		{
			ReliableSequenceNumber = command.ReliableSequenceNumber,
			UnreliableSequenceNumber = (ushort)(num & 0xFFFF),
			Command = command,
			FragmentCount = fragmentCount,
			FragmentsRemaining = fragmentCount,
			Packet = packet,
			Fragments = new BitArray((int)fragmentCount)
		};
		node.Next.Insert(value.Node);
		if (command is Protocol.Send.Fragment || command is Protocol.Send.Reliable)
		{
			DispatchIncomingReliableCommands(channel);
		}
		else
		{
			DispatchIncomingUnreliableCommands(channel);
		}
		return value;
	}
}
