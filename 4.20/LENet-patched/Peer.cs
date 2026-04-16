using System;
using System.Collections;

namespace LENet
{
    public enum PeerState
    {
        DISCONNECTED = 0,
        CONNECTING = 1,
        ACKNOWLEDGING_CONNECT = 2,
        CONNECTION_PENDING = 3,
        CONNECTION_SUCCEEDED = 4,
        CONNECTED = 5,
        DISCONNECT_LATER = 6,
        DISCONNECTING = 7,
        ACKNOWLEDGING_DISCONNECT = 8,
        ZOMBIE = 9,
    }

    public sealed class Peer : LList<Peer>.Element
    {
        public const ushort DEFAULT_ROUND_TRIP_TIME = 500;
        public const byte DEFAULT_PACKET_THROTTLE = 32;
        public const byte PACKET_THROTTLE_SCALE = 32;
        public const byte PACKET_THROTTLE_COUNTER = 7;
        public const byte PACKET_THROTTLE_ACCELERATION = 2;
        public const byte PACKET_THROTTLE_DECELERATION = 2;
        public const ushort PACKET_THROTTLE_INTERVAL = 5000;
        public const uint PACKET_LOSS_SCALE = (1 << 16);
        public const uint WINDOW_SIZE_SCALE = 64 * 1024;
        public const byte TIMEOUT_LIMIT = 32;
        public const ushort TIMEOUT_MINIMUM = 5000;
        public const ushort TIMEOUT_MAXIMUM = 30000;
        public const ushort PING_INTERVAL = 500;
        public const byte UNSEQUENCED_WINDOWS = 64;
        public const ushort UNSEQUENCED_WINDOW_SIZE = 1024;
        public const byte FREE_UNSEQUENCED_WINDOWS = 32;
        public const byte RELIABLE_WINDOWS = 16;
        public const ushort RELIABLE_WINDOW_SIZE = 0x1000;
        public const byte FREE_RELIABLE_WINDOWS = 8;
        public const uint FREE_RELIABLE_WINDOWS_MASK = (1u << FREE_RELIABLE_WINDOWS) - 1u;

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
        public BitArray UnsequencedWindow { get; } = new BitArray(UNSEQUENCED_WINDOW_SIZE);
        public uint DisconnectData { get; set; }

        public Peer(Host host, ushort id) 
        {
            Host = host;
            IncomingPeerID = id;
            Channels = new Channel[Host.ChannelLimit];
            for(var i = 0; i < Channels.Length; i++)
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

            var command = new Protocol.ThrottleConfigure
            {
                ChannelID = 0xFF,
                Flags = ProtocolFlag.ACKNOWLEDGE,
                PacketThrottleInterval = interval,
                PacketThrottleAcceleration = acceleration,
                PacketThrottleDeceleration = deceleration,
            };
            QueueOutgoingCommand(command, null, 0, 0);
        }

        public int Throttle(uint rtt)
        {
            if (LastRoundTripTime <= LastRoundTripTimeVariance)
            {
                PacketThrottle = PacketThrottleLimit;
            }
            else if (rtt < LastRoundTripTime)
            {
                PacketThrottle += PacketThrottleAcceleration;
                
                if(PacketThrottle > PacketThrottleLimit)
                {
                    PacketThrottle = PacketThrottleLimit;
                }

                return 1;
            }
            else if (rtt > LastRoundTripTime + 2u * LastRoundTripTimeVariance)
            {
                if (PacketThrottle > PacketThrottleDeceleration)
                {
                    PacketThrottle -= PacketThrottleDeceleration;
                }
                else
                {
                    PacketThrottle = 0;
                }

                return -1;
            }
            return 0;
        }

        public int Send(byte channelID, Packet packet)
        {
            if (State != PeerState.CONNECTED || channelID >= ChannelCount)
            {
                return -1;
            }

            var channel = Channels[channelID];

            uint fragmentLength = MTU - Host.Version.MaxHeaderSizeSend - Protocol.Send.Fragment.SIZE;
            
            if (packet.DataLength > fragmentLength)
            {
                ushort startSequenceNumber = (ushort)(channel.OutgoingReliableSequenceNumber + 1);
                uint fragmentCount = (packet.DataLength + fragmentLength - 1u) / fragmentLength;
                uint fragmentNumber = 0;
                uint fragmentOffset = 0;

                for (; fragmentOffset < packet.DataLength; 
                     fragmentOffset += fragmentLength, fragmentNumber++)
                {
                    if (packet.DataLength - fragmentOffset < fragmentLength)
                    {
                        fragmentLength = packet.DataLength - fragmentOffset;
                    }

                    var fragment = new OutgoingCommand
                    {
                        FragmentOffset = fragmentOffset,
                        FragmentLength = (ushort)fragmentLength,
                        Packet = packet,
                        Command = new Protocol.Send.Fragment
                        {
                            Flags = ProtocolFlag.ACKNOWLEDGE,
                            ChannelID = channelID,
                            StartSequenceNumber = startSequenceNumber,
                            DataLength = (ushort)fragmentLength,
                            FragmentCount = fragmentCount,
                            FragmentNumber = fragmentNumber,
                            TotalLength = packet.DataLength,
                            FragmentOffset = fragmentOffset,
                        }
                    };
                    SetupOutgoingCommand(fragment);
                }
                return 0;
            }


            Protocol command;
            if (packet.Flags.HasFlag(PacketFlags.RELIABLE))
            {
                command = new Protocol.Send.Reliable
                {
                    ChannelID = channelID,
                    Flags = ProtocolFlag.ACKNOWLEDGE,
                    DataLength = (ushort)packet.DataLength,
                };
            }
            else if (packet.Flags.HasFlag(PacketFlags.UNSEQUENCED))
            {
                command = new Protocol.Send.Unsequenced
                {
                    ChannelID = channelID,
                    Flags = ProtocolFlag.UNSEQUENCED,
                    UnsequencedGroup = (ushort)(OutgoingUnsequencedGroup + 1),
                    DataLength = (ushort)packet.DataLength,
                };
            }
            else if(channel.OutgoingReliableSequenceNumber >= 0xFFFFu)
            {
                command = new Protocol.Send.Reliable
                {
                    ChannelID = channelID,
                    Flags = ProtocolFlag.ACKNOWLEDGE,
                    DataLength = (ushort)packet.DataLength,
                };
            }
            else
            {
                command = new Protocol.Send.Unreliable
                {
                    ChannelID = channelID,
                    UnreliableSequenceNumber = (ushort)(channel.OutgoingUnreliableSequenceNumber + 1),
                    DataLength = (ushort)packet.DataLength,
                };
            }

            if(QueueOutgoingCommand(command, packet, 0, (ushort)packet.DataLength) == null)
            {
                return -1;
            }

            return 0;
        }

        public Packet Recieve(out byte ChannelID)
        {
            if (DispatchedCommands.Empty)
            {
                ChannelID = 0x00;
                return null;
            }

            var incomingCommand = DispatchedCommands.Begin.Remove().Value;
            
            ChannelID = incomingCommand.Command.ChannelID;
            
            return incomingCommand.Packet;
        }

        public void ResetChannels()
        {
            if (ChannelCount > 0)
            {
                foreach (var channel in Channels)
                {
                    Array.Clear(channel.ReliableWindows, 0, channel.ReliableWindows.Length);
                    channel.IncomingReliableCommands.Clear();
                    channel.IncomingUnreliableCommands.Clear();
                }

                ChannelCount = 0;
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
            SessionID = 0;

            State = PeerState.DISCONNECTED;

            IncomingBandwidth = 0;
            OutgoingBandwidth = 0;
            IncomingBandwidthThrottleEpoch = 0;
            OutgoingBandwidthThrottleEpoch = 0;
            IncomingDataTotal = 0;
            OutgoingDataTotal = 0;
            LastSendTime = 0;
            LastReceiveTime = 0;
            NextTimeout = 0;
            EarliestTimeout = 0;
            PacketLossEpoch = 0;
            PacketsSent = 0;
            PacketsLost = 0;
            PacketLoss = 0;
            PacketLossVariance = 0;
            PacketThrottle = DEFAULT_PACKET_THROTTLE;
            PacketThrottleLimit = PACKET_THROTTLE_SCALE;
            PacketThrottleCounter = 0;
            PacketThrottleEpoch = 0;
            PacketThrottleAcceleration = PACKET_THROTTLE_ACCELERATION;
            PacketThrottleDeceleration = PACKET_THROTTLE_DECELERATION;
            PacketThrottleInterval = PACKET_THROTTLE_INTERVAL;
            LastRoundTripTime = DEFAULT_ROUND_TRIP_TIME;
            LowestRoundTripTime = DEFAULT_ROUND_TRIP_TIME;
            LastRoundTripTimeVariance = 0;
            HighestRoundTripTimeVariance = 0;
            RoundTripTime = DEFAULT_ROUND_TRIP_TIME;
            RoundTripTimeVariance = 0;
            MTU = (ushort)Host.MTU;
            ReliableDataInTransit = 0;
            OutgoingReliableSequenceNumber = 0;
            WindowSize = Host.MAXIMUM_WINDOW_SIZE;
            IncomingUnsequencedGroup = 0;
            OutgoingUnsequencedGroup = 0;
            DisconnectData = 0;

            UnsequencedWindow.SetAll(false);
            ResetQueues();
        }

        public void Ping()
        {
            if(State != PeerState.CONNECTED)
            {
                return;
            }

            var command = new Protocol.Ping
            {
                ChannelID = 0xFF,
                Flags = ProtocolFlag.ACKNOWLEDGE,
            };

            QueueOutgoingCommand(command, null, 0, 0);
        }

        public void DisconnectNow(uint data)
        {
            if (State == PeerState.DISCONNECTED)
            {
                return;
            }

            if (State != PeerState.ZOMBIE && State != PeerState.DISCONNECTING)
            {
                ResetQueues();

                var command = new Protocol.Disconnect
                {
                    Flags = ProtocolFlag.UNSEQUENCED,
                    ChannelID = 0xFF,
                    Data = data,
                };

                QueueOutgoingCommand(command, null, 0, 0);

                Host.Flush();
            }
            Reset();
        }

        public void Disconnect(uint data)
        {
            if (State == PeerState.DISCONNECTING
                || State == PeerState.DISCONNECTED
                || State == PeerState.ACKNOWLEDGING_DISCONNECT
                || State == PeerState.ZOMBIE)
            {
                return;
            }

            ResetQueues();
            
            var command = new Protocol.Disconnect
            {
                ChannelID = 0xFF,
                Data = data,
            };

            if(State == PeerState.CONNECTED || State == PeerState.DISCONNECT_LATER)
            {
                command.Flags |= ProtocolFlag.ACKNOWLEDGE;
            }
            else
            {
                command.Flags |= ProtocolFlag.UNSEQUENCED;
            }


            QueueOutgoingCommand(command, null, 0, 0);

            if (State == PeerState.CONNECTED || State == PeerState.DISCONNECT_LATER)
            {
                State = PeerState.DISCONNECTING;
            }
            else
            {
                Host.Flush();
                Reset();
            }
        }

        public void DisconnectLater(uint data)
        {
            if ((State == PeerState.CONNECTED || State == PeerState.DISCONNECT_LATER)
                && !(OutgoingReliableCommands.Empty 
                     && OutgoingUnreliableCommands.Empty 
                     && SentReliableCommands.Empty))
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
                var channel = Channels[command.ChannelID];
                ushort reliableWindow = (ushort)(command.ReliableSequenceNumber / RELIABLE_WINDOW_SIZE);
                ushort currentWindow = (ushort)(channel.IncomingReliableSequenceNumber / RELIABLE_WINDOW_SIZE);
                
                if (command.ReliableSequenceNumber < channel.IncomingReliableSequenceNumber)
                {
                    reliableWindow += RELIABLE_WINDOWS;
                }

                if (reliableWindow >= currentWindow + FREE_RELIABLE_WINDOWS - 1 && reliableWindow <= currentWindow + FREE_RELIABLE_WINDOWS)
                {
                    return null;
                }
            }

            var acknowledgement = new Acknowledgement
            {
                SentTime = sentTime,
                Command = command
            };

            OutgoingDataTotal += Protocol.Acknowledge.SIZE;

            Acknowledgements.End.Insert(acknowledgement.Node);

            return acknowledgement;
        }

        public void SetupOutgoingCommand(OutgoingCommand outgoingCommand)
        {
            OutgoingDataTotal += (uint)outgoingCommand.Command.Size + outgoingCommand.FragmentLength;
            
            if (outgoingCommand.Command.ChannelID == 0xFF)
            {
                OutgoingReliableSequenceNumber++;

                outgoingCommand.ReliableSequenceNumber = OutgoingReliableSequenceNumber;
                outgoingCommand.UnreliableSequenceNumber = 0;
            }
            else
            {
                var channel = Channels[outgoingCommand.Command.ChannelID];
                
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
            outgoingCommand.SentTime = 0;
            outgoingCommand.RoundTripTimeout = 0;
            outgoingCommand.RoundTripTimeoutLimit = 0;
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
            var outgoingCommand = new OutgoingCommand
            {
                Command = command,
                FragmentOffset = offset,
                FragmentLength = length,
                Packet = packet,
            };

            SetupOutgoingCommand(outgoingCommand);

            return outgoingCommand;
        }

        public void DispatchIncomingUnreliableCommands(Channel channel)
        {
            LList<IncomingCommand>.Node currentCommand;
            for (currentCommand = channel.IncomingUnreliableCommands.Begin;
                 currentCommand != channel.IncomingUnreliableCommands.End; 
                 currentCommand = currentCommand.Next)
            {
                var incomingCommand = currentCommand.Value;

                if (incomingCommand.Command is Protocol.Send.Unreliable)
                {
                    if (incomingCommand.ReliableSequenceNumber != channel.IncomingReliableSequenceNumber)
                    {
                        break;
                    }
                    channel.IncomingUnreliableSequenceNumber = incomingCommand.UnreliableSequenceNumber;
                }
            }

            if (currentCommand == channel.IncomingUnreliableCommands.Begin)
            {
                return;
            }

            DispatchedCommands.End.Move(channel.IncomingUnreliableCommands.Begin, currentCommand.Prev);

            if (!NeedsDispatch)
            {
                Host.DispatchQueue.End.Insert(Node);

                NeedsDispatch = true;
            }
        }

        public void DispatchIncomingReliableCommands(Channel channel)
        {
            LList<IncomingCommand>.Node currentCommand;

            for (currentCommand = channel.IncomingReliableCommands.Begin;
                 currentCommand != channel.IncomingReliableCommands.End; 
                 currentCommand = currentCommand.Next)
            {
                var incomingCommand = currentCommand.Value;

                if(incomingCommand.FragmentsRemaining > 0 
                    || incomingCommand.ReliableSequenceNumber != (ushort)(channel.IncomingReliableSequenceNumber + 1))
                {
                    break;
                }

                channel.IncomingReliableSequenceNumber = incomingCommand.ReliableSequenceNumber;
                
                if(incomingCommand.FragmentCount > 0)
                {
                    channel.IncomingReliableSequenceNumber += (ushort)(incomingCommand.FragmentCount - 1);
                }
            }

            if (currentCommand == channel.IncomingReliableCommands.Begin)
            {
                return;
            }

            channel.IncomingUnreliableSequenceNumber = 0;

            DispatchedCommands.End.Move(channel.IncomingReliableCommands.Begin, currentCommand.Prev);

            if (!NeedsDispatch)
            {
                Host.DispatchQueue.End.Insert(Node);

                NeedsDispatch = true;
            }

            DispatchIncomingUnreliableCommands(channel);
        }
        
        public IncomingCommand QueueIncomingCommand(Protocol command, Packet packet, uint fragmentCount)
        {
            Channel channel = command.ChannelID == 0xFF ? null : Channels[command.ChannelID];

            var notifyError = fragmentCount > 0 ? null : new IncomingCommand();

            if (State == PeerState.DISCONNECT_LATER)
            {
                return notifyError;
            }

            uint unreliableSequenceNumber = 0;
            uint reliableSequenceNumber = 0;

            if (!(command is Protocol.Send.Unsequenced))
            {
                reliableSequenceNumber = command.ReliableSequenceNumber;
                ushort reliableWindow = (ushort)(reliableSequenceNumber / RELIABLE_WINDOW_SIZE);
                ushort currentWindow = (ushort)(channel.IncomingReliableSequenceNumber / RELIABLE_WINDOW_SIZE);
                
                if(reliableSequenceNumber < channel.IncomingReliableSequenceNumber)
                {
                    reliableWindow += RELIABLE_WINDOWS;
                }
                
                if (reliableWindow < currentWindow || reliableWindow >= currentWindow + FREE_RELIABLE_WINDOWS - 1u)
                {
                    return notifyError;
                }
            }


            LList<IncomingCommand>.Node currentCommand;
            IncomingCommand incomingCommand;
            switch (command)
            {
                case Protocol.Send.Fragment _:
                case Protocol.Send.Reliable _: 
                    if(reliableSequenceNumber == channel.IncomingReliableSequenceNumber)
                    {
                        return notifyError;
                    }

                    for (currentCommand = channel.IncomingReliableCommands.End.Prev; 
                         currentCommand != channel.IncomingReliableCommands.End; 
                         currentCommand = currentCommand.Prev)
                    {
                        incomingCommand = currentCommand.Value;

                        if (reliableSequenceNumber >= channel.IncomingReliableSequenceNumber)
                        {
                            if (incomingCommand.ReliableSequenceNumber < channel.IncomingReliableSequenceNumber)
                            {
                                continue;
                            }
                        }
                        else if (incomingCommand.ReliableSequenceNumber >= channel.IncomingReliableSequenceNumber)
                        {
                            break;
                        }

                        if (incomingCommand.ReliableSequenceNumber <= reliableSequenceNumber)
                        {
                            if (incomingCommand.ReliableSequenceNumber < reliableSequenceNumber)
                            {
                                break;
                            }

                            return notifyError;
                        }
                    }
                    break;

                case Protocol.Send.Unreliable sendUnreliable:
                    unreliableSequenceNumber = sendUnreliable.UnreliableSequenceNumber;

                    if (reliableSequenceNumber == channel.IncomingReliableSequenceNumber
                        && unreliableSequenceNumber <= channel.IncomingUnreliableSequenceNumber)
                    {
                        return notifyError;
                    }

                    for (currentCommand = channel.IncomingUnreliableCommands.End.Prev; 
                         currentCommand != channel.IncomingUnreliableCommands.End; 
                         currentCommand = currentCommand.Prev)
                    {
                        incomingCommand = currentCommand.Value;
                        
                        if(!(incomingCommand.Command is Protocol.Send.Unreliable))
                        {
                            continue;
                        }

                        if (reliableSequenceNumber >= channel.IncomingReliableSequenceNumber)
                        {
                            if (incomingCommand.ReliableSequenceNumber < channel.IncomingReliableSequenceNumber)
                            {
                                continue;
                            }
                        }
                        else if (incomingCommand.ReliableSequenceNumber >= channel.IncomingReliableSequenceNumber)
                        {
                            break;
                        }

                        if (incomingCommand.ReliableSequenceNumber < reliableSequenceNumber)
                        {
                            break;
                        }

                        if (incomingCommand.ReliableSequenceNumber > reliableSequenceNumber)
                        { 
                            continue;
                        }

                        if (incomingCommand.UnreliableSequenceNumber <= unreliableSequenceNumber)
                        {
                            if (incomingCommand.UnreliableSequenceNumber < unreliableSequenceNumber)
                            {
                                break;
                            }

                            return notifyError;
                        }
                    }

                    break;
                case Protocol.Send.Unsequenced _:
                    currentCommand = channel.IncomingUnreliableCommands.End;
                    break;
                default:
                    return notifyError;
            }

            incomingCommand = new IncomingCommand
            {
                ReliableSequenceNumber = command.ReliableSequenceNumber,
                UnreliableSequenceNumber = (ushort)(unreliableSequenceNumber & 0xFFFF),
                Command = command,
                FragmentCount = fragmentCount,
                FragmentsRemaining = fragmentCount,
                Packet = packet,
                Fragments = new BitArray((int)fragmentCount), // CHECKME: (fragmentCount + 31) / 32
            };

            currentCommand.Next.Insert(incomingCommand.Node);

            switch (command)
            {
                case Protocol.Send.Fragment _:
                case Protocol.Send.Reliable _:
                    DispatchIncomingReliableCommands(channel);
                    break;
                default:
                    DispatchIncomingUnreliableCommands(channel);
                    break;
            }

            return incomingCommand;
        }
    }
}
