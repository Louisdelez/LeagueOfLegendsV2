namespace LENet;

public abstract class Protocol
{
	public sealed class Acknowledge : Protocol
	{
		public const byte SIZE = 8;

		public ushort ReceivedReliableSequenceNumber { get; set; }

		public ushort ReceivedSentTime { get; set; }

		public override byte Size => 8;

		public override ProtocolCommand Command => ProtocolCommand.ACKNOWLEDGE;

		protected override void ReadInternal(Buffer reader, Version version)
		{
			ReceivedReliableSequenceNumber = reader.ReadUInt16();
			ReceivedSentTime = reader.ReadUInt16();
		}

		protected override void WriteInternal(Buffer writer, Version version)
		{
			writer.WriteUInt16(ReceivedReliableSequenceNumber);
			writer.WriteUInt16(ReceivedSentTime);
		}
	}

	public sealed class Connect : Protocol
	{
		public const byte SIZE = 40;

		public ushort OutgoingPeerID { get; set; }

		public ushort MTU { get; set; }

		public uint WindowSize { get; set; }

		public uint ChannelCount { get; set; }

		public uint IncomingBandwidth { get; set; }

		public uint OutgoingBandwidth { get; set; }

		public uint PacketThrottleInterval { get; set; }

		public uint PacketThrottleAcceleration { get; set; }

		public uint PacketThrottleDeceleration { get; set; }

		public uint SessionID { get; set; }

		public override byte Size => 40;

		public override ProtocolCommand Command => ProtocolCommand.CONNECT;

		protected override void ReadInternal(Buffer reader, Version version)
		{
			if (version.MaxPeerID > 127)
			{
				OutgoingPeerID = reader.ReadUInt16();
			}
			else
			{
				OutgoingPeerID = reader.ReadByte();
				reader.Position++;
			}
			MTU = reader.ReadUInt16();
			WindowSize = reader.ReadUInt32();
			ChannelCount = reader.ReadUInt32();
			IncomingBandwidth = reader.ReadUInt32();
			OutgoingBandwidth = reader.ReadUInt32();
			PacketThrottleInterval = reader.ReadUInt32();
			PacketThrottleAcceleration = reader.ReadUInt32();
			PacketThrottleDeceleration = reader.ReadUInt32();
			if (version.MaxPeerID > 127)
			{
				SessionID = reader.ReadUInt32();
				return;
			}
			SessionID = reader.ReadByte();
			reader.Position += 3u;
		}

		protected override void WriteInternal(Buffer writer, Version version)
		{
			if (version.MaxPeerID > 127)
			{
				writer.WriteUInt16(OutgoingPeerID);
			}
			else
			{
				writer.WriteByte((byte)OutgoingPeerID);
				writer.Position++;
			}
			writer.WriteUInt16(MTU);
			writer.WriteUInt32(WindowSize);
			writer.WriteUInt32(ChannelCount);
			writer.WriteUInt32(IncomingBandwidth);
			writer.WriteUInt32(OutgoingBandwidth);
			writer.WriteUInt32(PacketThrottleInterval);
			writer.WriteUInt32(PacketThrottleAcceleration);
			writer.WriteUInt32(PacketThrottleDeceleration);
			if (version.MaxPeerID > 127)
			{
				writer.WriteUInt32(SessionID);
				return;
			}
			writer.WriteByte((byte)SessionID);
			writer.Position += 3u;
		}
	}

	public sealed class VerifyConnect : Protocol
	{
		public const byte SIZE = 36;

		public ushort OutgoingPeerID { get; set; }

		public ushort MTU { get; set; }

		public uint WindowSize { get; set; }

		public uint ChannelCount { get; set; }

		public uint IncomingBandwidth { get; set; }

		public uint OutgoingBandwidth { get; set; }

		public uint PacketThrottleInterval { get; set; }

		public uint PacketThrottleAcceleration { get; set; }

		public uint PacketThrottleDeceleration { get; set; }

		public override byte Size => 36;

		public override ProtocolCommand Command => ProtocolCommand.VERIFY_CONNECT;

		protected override void ReadInternal(Buffer reader, Version version)
		{
			if (version.MaxPeerID > 127)
			{
				OutgoingPeerID = reader.ReadUInt16();
			}
			else
			{
				OutgoingPeerID = reader.ReadByte();
				reader.Position++;
			}
			MTU = reader.ReadUInt16();
			WindowSize = reader.ReadUInt32();
			ChannelCount = reader.ReadUInt32();
			IncomingBandwidth = reader.ReadUInt32();
			OutgoingBandwidth = reader.ReadUInt32();
			PacketThrottleInterval = reader.ReadUInt32();
			PacketThrottleAcceleration = reader.ReadUInt32();
			PacketThrottleDeceleration = reader.ReadUInt32();
		}

		protected override void WriteInternal(Buffer writer, Version version)
		{
			if (version.MaxPeerID > 127)
			{
				writer.WriteUInt16(OutgoingPeerID);
			}
			else
			{
				writer.WriteByte((byte)OutgoingPeerID);
				writer.Position++;
			}
			writer.WriteUInt16(MTU);
			writer.WriteUInt32(WindowSize);
			writer.WriteUInt32(ChannelCount);
			writer.WriteUInt32(IncomingBandwidth);
			writer.WriteUInt32(OutgoingBandwidth);
			writer.WriteUInt32(PacketThrottleInterval);
			writer.WriteUInt32(PacketThrottleAcceleration);
			writer.WriteUInt32(PacketThrottleDeceleration);
		}
	}

	public sealed class BandwidthLimit : Protocol
	{
		public const byte SIZE = 12;

		public uint IncomingBandwidth { get; set; }

		public uint OutgoingBandwidth { get; set; }

		public override byte Size => 12;

		public override ProtocolCommand Command => ProtocolCommand.BANDWIDTH_LIMIT;

		protected override void ReadInternal(Buffer reader, Version version)
		{
			IncomingBandwidth = reader.ReadUInt32();
			OutgoingBandwidth = reader.ReadUInt32();
		}

		protected override void WriteInternal(Buffer writer, Version version)
		{
			writer.WriteUInt32(IncomingBandwidth);
			writer.WriteUInt32(OutgoingBandwidth);
		}
	}

	public sealed class ThrottleConfigure : Protocol
	{
		public const byte SIZE = 16;

		public uint PacketThrottleInterval { get; set; }

		public uint PacketThrottleAcceleration { get; set; }

		public uint PacketThrottleDeceleration { get; set; }

		public override byte Size => 16;

		public override ProtocolCommand Command => ProtocolCommand.THROTTLE_CONFIGURE;

		protected override void ReadInternal(Buffer reader, Version version)
		{
			PacketThrottleInterval = reader.ReadUInt32();
			PacketThrottleAcceleration = reader.ReadUInt32();
			PacketThrottleDeceleration = reader.ReadUInt32();
		}

		protected override void WriteInternal(Buffer writer, Version version)
		{
			writer.WriteUInt32(PacketThrottleInterval);
			writer.WriteUInt32(PacketThrottleAcceleration);
			writer.WriteUInt32(PacketThrottleDeceleration);
		}
	}

	public sealed class Disconnect : Protocol
	{
		public const byte SIZE = 8;

		public uint Data { get; set; }

		public override byte Size => 8;

		public override ProtocolCommand Command => ProtocolCommand.DISCONNECT;

		protected override void ReadInternal(Buffer reader, Version version)
		{
			Data = reader.ReadUInt32();
		}

		protected override void WriteInternal(Buffer writer, Version version)
		{
			writer.WriteUInt32(Data);
		}
	}

	public sealed class Ping : Protocol
	{
		public const byte SIZE = 4;

		public override byte Size => 4;

		public override ProtocolCommand Command => ProtocolCommand.PING;

		protected override void ReadInternal(Buffer reader, Version version)
		{
		}

		protected override void WriteInternal(Buffer writer, Version version)
		{
		}
	}

	public sealed class None : Protocol
	{
		public const byte SIZE = 4;

		public override byte Size => 4;

		public override ProtocolCommand Command => ProtocolCommand.NONE;

		protected override void ReadInternal(Buffer reader, Version version)
		{
		}

		protected override void WriteInternal(Buffer writer, Version version)
		{
		}
	}

	public abstract class Send : Protocol
	{
		public sealed class Reliable : Protocol
		{
			public const byte SIZE = 6;

			public ushort DataLength { get; set; }

			public override byte Size => 6;

			public override ProtocolCommand Command => ProtocolCommand.SEND_RELIABLE;

			protected override void ReadInternal(Buffer reader, Version version)
			{
				DataLength = reader.ReadUInt16();
			}

			protected override void WriteInternal(Buffer writer, Version version)
			{
				writer.WriteUInt16(DataLength);
			}
		}

		public sealed class Unreliable : Protocol
		{
			public const byte SIZE = 8;

			public ushort UnreliableSequenceNumber { get; set; }

			public ushort DataLength { get; set; }

			public override byte Size => 8;

			public override ProtocolCommand Command => ProtocolCommand.SEND_UNRELIABLE;

			protected override void ReadInternal(Buffer reader, Version version)
			{
				UnreliableSequenceNumber = reader.ReadUInt16();
				DataLength = reader.ReadUInt16();
			}

			protected override void WriteInternal(Buffer writer, Version version)
			{
				writer.WriteUInt16(UnreliableSequenceNumber);
				writer.WriteUInt16(DataLength);
			}
		}

		public sealed class Unsequenced : Protocol
		{
			public const byte SIZE = 8;

			public ushort UnsequencedGroup { get; set; }

			public ushort DataLength { get; set; }

			public override byte Size => 8;

			public override ProtocolCommand Command => ProtocolCommand.SEND_UNSEQUENCED;

			protected override void ReadInternal(Buffer reader, Version version)
			{
				UnsequencedGroup = reader.ReadUInt16();
				DataLength = reader.ReadUInt16();
			}

			protected override void WriteInternal(Buffer writer, Version version)
			{
				writer.WriteUInt16(UnsequencedGroup);
				writer.WriteUInt16(DataLength);
			}
		}

		public sealed class Fragment : Protocol
		{
			public const byte SIZE = 24;

			public ushort StartSequenceNumber { get; set; }

			public ushort DataLength { get; set; }

			public uint FragmentCount { get; set; }

			public uint FragmentNumber { get; set; }

			public uint TotalLength { get; set; }

			public uint FragmentOffset { get; set; }

			public override byte Size => 24;

			public override ProtocolCommand Command => ProtocolCommand.SEND_FRAGMENT;

			protected override void ReadInternal(Buffer reader, Version version)
			{
				StartSequenceNumber = reader.ReadUInt16();
				DataLength = reader.ReadUInt16();
				FragmentCount = reader.ReadUInt32();
				FragmentNumber = reader.ReadUInt32();
				TotalLength = reader.ReadUInt32();
				FragmentOffset = reader.ReadUInt32();
			}

			protected override void WriteInternal(Buffer writer, Version version)
			{
				writer.WriteUInt16(StartSequenceNumber);
				writer.WriteUInt16(DataLength);
				writer.WriteUInt32(FragmentCount);
				writer.WriteUInt32(FragmentNumber);
				writer.WriteUInt32(TotalLength);
				writer.WriteUInt32(FragmentOffset);
			}
		}

		public abstract ushort DataLength { get; set; }

		private Send()
		{
		}
	}

	public const byte BASE_SIZE = 4;

	public ProtocolFlag Flags { get; set; }

	public byte ChannelID { get; set; }

	public ushort ReliableSequenceNumber { get; set; }

	public abstract byte Size { get; }

	public abstract ProtocolCommand Command { get; }

	protected abstract void ReadInternal(Buffer reader, Version version);

	protected abstract void WriteInternal(Buffer writer, Version version);

	private Protocol()
	{
	}

	public static Protocol Create(Buffer reader, Version version)
	{
		if (4 > reader.BytesLeft)
		{
			return null;
		}
		byte b = reader.ReadByte();
		byte channelID = reader.ReadByte();
		ushort reliableSequenceNumber = reader.ReadUInt16();
		Protocol protocol = (ProtocolCommand)(b & 0xF) switch
		{
			ProtocolCommand.NONE => null, 
			ProtocolCommand.ACKNOWLEDGE => new Acknowledge(), 
			ProtocolCommand.CONNECT => new Connect(), 
			ProtocolCommand.VERIFY_CONNECT => new VerifyConnect(), 
			ProtocolCommand.DISCONNECT => new Disconnect(), 
			ProtocolCommand.PING => new Ping(), 
			ProtocolCommand.SEND_FRAGMENT => new Send.Fragment(), 
			ProtocolCommand.SEND_RELIABLE => new Send.Reliable(), 
			ProtocolCommand.SEND_UNRELIABLE => new Send.Unreliable(), 
			ProtocolCommand.SEND_UNSEQUENCED => new Send.Unsequenced(), 
			ProtocolCommand.BANDWIDTH_LIMIT => new BandwidthLimit(), 
			ProtocolCommand.THROTTLE_CONFIGURE => new ThrottleConfigure(), 
			_ => null, 
		};
		if (protocol == null || protocol.Size - 4 > reader.BytesLeft)
		{
			return null;
		}
		protocol.ChannelID = channelID;
		protocol.Flags = (ProtocolFlag)(b & 0xF0);
		protocol.ReliableSequenceNumber = reliableSequenceNumber;
		protocol.ReadInternal(reader, version);
		return protocol;
	}

	public void Write(Buffer writer, Version version)
	{
		writer.WriteByte((byte)((uint)Flags | (uint)(byte)Command));
		writer.WriteByte(ChannelID);
		writer.WriteUInt16(ReliableSequenceNumber);
		WriteInternal(writer, version);
	}
}
