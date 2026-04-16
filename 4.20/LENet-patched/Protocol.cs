using System;

namespace LENet
{
    public abstract class Protocol
    {
        public ProtocolFlag Flags { get; set; }
        public byte ChannelID { get; set; }
        public ushort ReliableSequenceNumber { get; set; }
        public abstract byte Size { get; }
        public abstract ProtocolCommand Command { get; }
        
        public const byte BASE_SIZE = 4;

        protected abstract void ReadInternal(Buffer reader, Version version);
        protected abstract void WriteInternal(Buffer writer, Version version);

        private Protocol() { }

        public static Protocol Create(Buffer reader, Version version)
        {
            if(BASE_SIZE > reader.BytesLeft)
            {
                return null;
            }

            byte command_flags = reader.ReadByte();
            var channel = reader.ReadByte();
            var reliableSequenceNumber = reader.ReadUInt16();

            Protocol result;
            switch ((ProtocolCommand)(command_flags & 0x0Fu))
            {
                case ProtocolCommand.NONE: result = null; break;
                case ProtocolCommand.ACKNOWLEDGE: result = new Acknowledge(); break;
                case ProtocolCommand.CONNECT: result = new Connect(); break;
                case ProtocolCommand.VERIFY_CONNECT: result = new VerifyConnect(); break;
                case ProtocolCommand.DISCONNECT: result = new Disconnect(); break;
                case ProtocolCommand.PING: result = new Ping(); break;
                case ProtocolCommand.SEND_FRAGMENT: result = new Send.Fragment(); break;
                case ProtocolCommand.SEND_RELIABLE: result = new Send.Reliable(); break;
                case ProtocolCommand.SEND_UNRELIABLE: result = new Send.Unreliable(); break;
                case ProtocolCommand.SEND_UNSEQUENCED: result = new Send.Unsequenced(); break;
                case ProtocolCommand.BANDWIDTH_LIMIT: result = new BandwidthLimit(); break;
                case ProtocolCommand.THROTTLE_CONFIGURE: result = new ThrottleConfigure(); break;
                default: result = null; break;
            };

            if (result == null || (result.Size - BASE_SIZE) > reader.BytesLeft)
            {
                return null;
            }

            result.ChannelID = channel;
            result.Flags = (ProtocolFlag)(command_flags & 0xF0);
            result.ReliableSequenceNumber = reliableSequenceNumber;
            result.ReadInternal(reader, version);

            return result;
        }

        public void Write(Buffer writer, Version version)
        {
            writer.WriteByte((byte)((byte)Flags | (byte)(Command)));
            writer.WriteByte(ChannelID);
            writer.WriteUInt16(ReliableSequenceNumber);
            WriteInternal(writer, version);
        }

        public sealed class Acknowledge : Protocol
        {
            public ushort ReceivedReliableSequenceNumber { get; set; }
            public ushort ReceivedSentTime { get; set; }
            public const byte SIZE = 4 + 4;
            public override byte Size => SIZE;
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

            public const byte SIZE = 4 + 36;
            public override byte Size => SIZE;
            public override ProtocolCommand Command => ProtocolCommand.CONNECT;

            protected override void ReadInternal(Buffer reader, Version version)
            {
                if (version.MaxPeerID > 0x7F)
                {
                    OutgoingPeerID = reader.ReadUInt16();
                }
                else
                {
                    OutgoingPeerID = reader.ReadByte();
                    reader.Position += 1;
                }

                MTU = reader.ReadUInt16();
                WindowSize = reader.ReadUInt32();
                ChannelCount = reader.ReadUInt32();
                IncomingBandwidth = reader.ReadUInt32();
                OutgoingBandwidth = reader.ReadUInt32();
                PacketThrottleInterval = reader.ReadUInt32();
                PacketThrottleAcceleration = reader.ReadUInt32();
                PacketThrottleDeceleration = reader.ReadUInt32();

                if (version.MaxPeerID > 0x7F)
                {
                    SessionID = reader.ReadUInt32();
                }
                else
                {
                    SessionID = reader.ReadByte();
                    reader.Position += 3;
                }
            }

            protected override void WriteInternal(Buffer writer, Version version)
            {
                if (version.MaxPeerID > 0x7F)
                {
                    writer.WriteUInt16(OutgoingPeerID);
                }
                else
                {
                    writer.WriteByte((byte)OutgoingPeerID);
                    writer.Position += 1;
                }

                writer.WriteUInt16(MTU);
                writer.WriteUInt32(WindowSize);
                writer.WriteUInt32(ChannelCount);
                writer.WriteUInt32(IncomingBandwidth);
                writer.WriteUInt32(OutgoingBandwidth);
                writer.WriteUInt32(PacketThrottleInterval);
                writer.WriteUInt32(PacketThrottleAcceleration);
                writer.WriteUInt32(PacketThrottleDeceleration);

                if (version.MaxPeerID > 0x7F)
                {
                    writer.WriteUInt32(SessionID);
                }
                else
                {
                    writer.WriteByte((byte)SessionID);
                    writer.Position += 3;
                }
            }
        }

        public sealed class VerifyConnect : Protocol
        {
            public ushort OutgoingPeerID { get; set; }
            public ushort MTU { get; set; }
            public uint WindowSize { get; set; }
            public uint ChannelCount { get; set; }
            public uint IncomingBandwidth { get; set; }
            public uint OutgoingBandwidth { get; set; }
            public uint PacketThrottleInterval { get; set; }
            public uint PacketThrottleAcceleration { get; set; }
            public uint PacketThrottleDeceleration { get; set; }

            public const byte SIZE = 4 + 32;
            public override byte Size => SIZE;
            public override ProtocolCommand Command => ProtocolCommand.VERIFY_CONNECT;

            protected override void ReadInternal(Buffer reader, Version version)
            {
                if (version.MaxPeerID > 0x7F)
                {
                    OutgoingPeerID = reader.ReadUInt16();
                }
                else
                {
                    OutgoingPeerID = reader.ReadByte();
                    reader.Position += 1;
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
                if (version.MaxPeerID > 0x7F)
                {
                    writer.WriteUInt16(OutgoingPeerID);
                }
                else
                {
                    writer.WriteByte((byte)OutgoingPeerID);
                    writer.Position += 1;
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
            public uint IncomingBandwidth { get; set; }
            public uint OutgoingBandwidth { get; set; }

            public const byte SIZE = 4 + 8;
            public override byte Size => SIZE;
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
            public uint PacketThrottleInterval { get; set; }
            public uint PacketThrottleAcceleration { get; set; }
            public uint PacketThrottleDeceleration { get; set; }

            public const byte SIZE = 4 + 12;
            public override byte Size => SIZE;
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
            public uint Data { get; set; }

            public const byte SIZE = 4 + 4;
            public override byte Size => SIZE;
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
            public const byte SIZE = 4 + 0;
            public override byte Size => SIZE;
            public override ProtocolCommand Command => ProtocolCommand.PING;

            protected override void ReadInternal(Buffer reader, Version version) { }
            protected override void WriteInternal(Buffer writer, Version version) { }
        }

        public sealed class None : Protocol
        {
            public const byte SIZE = 4 + 0;
            public override byte Size => SIZE;
            public override ProtocolCommand Command => ProtocolCommand.NONE;

            protected override void ReadInternal(Buffer reader, Version version) { }
            protected override void WriteInternal(Buffer writer, Version version) { }
        }

        public abstract class Send : Protocol
        {
            public abstract ushort DataLength { get; set; }
            private Send() { }

            public sealed class Reliable : Protocol
            {
                public ushort DataLength { get; set; }

                public const byte SIZE = 4 + 2;
                public override byte Size => SIZE;
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
                public ushort UnreliableSequenceNumber { get; set; }
                public ushort DataLength { get; set; }

                public const byte SIZE = 4 + 4;
                public override byte Size => SIZE;
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
                public ushort UnsequencedGroup { get; set; }
                public ushort DataLength { get; set; }

                public const byte SIZE = 4 + 4;
                public override byte Size => SIZE;
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
                public ushort StartSequenceNumber { get; set; }
                public ushort DataLength { get; set; }
                public uint FragmentCount { get; set; }
                public uint FragmentNumber { get; set; }
                public uint TotalLength { get; set; }
                public uint FragmentOffset { get; set; }

                public const byte SIZE = 4 + 20;
                public override byte Size => SIZE;
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
        }
    }
}
