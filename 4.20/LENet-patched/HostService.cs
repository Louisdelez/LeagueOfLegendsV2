using System;
using System.Net.Sockets;

namespace LENet
{
    public sealed partial class Host : IDisposable
    {
        private int DispatchIncomingCommands(Event evnt)
        {
            while (!DispatchQueue.Empty)
            {
                var peer = DispatchQueue.Begin.Remove().Value;
                
                peer.NeedsDispatch = false;

                switch (peer.State)
                {
                    case PeerState.CONNECTION_PENDING:
                    case PeerState.CONNECTION_SUCCEEDED:
                        peer.State = PeerState.CONNECTED;

                        evnt.Type = EventType.CONNECT;
                        evnt.Peer = peer;

                        return 1;

                    case PeerState.ZOMBIE:
                        RecalculateBandwidthLimits = true;

                        evnt.Type = EventType.DISCONNECT;
                        evnt.Peer = peer;
                        evnt.Data = peer.DisconnectData;

                        peer.Reset();

                        return 1;

                    case PeerState.CONNECTED:
                        if (peer.DispatchedCommands.Empty)
                        {
                            continue;
                        }

                        evnt.Packet = peer.Recieve(out byte channelID);

                        if (evnt.Packet == null)
                        {
                            continue;
                        }

                        evnt.ChannelID = channelID;
                        evnt.Type = EventType.RECEIVE;
                        evnt.Peer = peer;

                        if (!peer.DispatchedCommands.Empty)
                        {
                            peer.NeedsDispatch = true;
                            
                            DispatchQueue.End.Insert(peer.Node);
                        }

                        return 1;
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
                DispatchState(peer, peer.State == PeerState.CONNECTING ? PeerState.CONNECTION_SUCCEEDED : PeerState.CONNECTION_PENDING);
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
                evnt.Data = 0;

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
            LList<OutgoingCommand>.Node currentCommand;
            OutgoingCommand outgoingCommand = null;
            bool wasSent = true;

            for (currentCommand = peer.SentReliableCommands.Begin;
                 currentCommand != peer.SentReliableCommands.End;
                 currentCommand = currentCommand.Next)
            {
                outgoingCommand = currentCommand.Value;

                if (outgoingCommand.ReliableSequenceNumber == reliableSequenceNumber
                    && outgoingCommand.Command.ChannelID == channelID)
                {
                    break;
                }
            }

            if (currentCommand == peer.SentReliableCommands.End)
            {
                for (currentCommand = peer.OutgoingReliableCommands.Begin;
                     currentCommand != peer.OutgoingReliableCommands.End;
                     currentCommand = currentCommand.Next)
                {
                    outgoingCommand = currentCommand.Value;

                    if (outgoingCommand.SendAttempts < 1)
                    {
                        return ProtocolCommand.NONE;
                    }

                    if (outgoingCommand.ReliableSequenceNumber == reliableSequenceNumber
                        && outgoingCommand.Command.ChannelID == channelID)
                    {
                        break;
                    }
                }

                if (currentCommand == peer.OutgoingReliableCommands.End)
                {
                    return ProtocolCommand.NONE;
                }

                wasSent = false;
            }

            if (channelID < peer.ChannelCount)
            {
                var channel = peer.Channels[channelID];
                ushort reliableWindow = (ushort)(reliableSequenceNumber / Peer.RELIABLE_WINDOW_SIZE);
                if (channel.ReliableWindows[reliableWindow] > 0)
                {
                    channel.ReliableWindows[reliableWindow]--;
                    if (channel.ReliableWindows[reliableWindow] == 0)
                    {
                        channel.UsedReliableWindows &= (ushort)~(1u << reliableWindow);
                    }
                }
            }

            var commandNumber = outgoingCommand.Command.Command;
            outgoingCommand.Node.Remove();

            if (outgoingCommand.Packet != null)
            {
                if (wasSent)
                {
                    peer.ReliableDataInTransit -= outgoingCommand.FragmentLength;
                }
            }

            if (peer.SentReliableCommands.Empty)
            {
                return commandNumber;
            }

            outgoingCommand = peer.SentReliableCommands.Begin.Value;

            peer.NextTimeout = outgoingCommand.SentTime + outgoingCommand.RoundTripTimeout;

            return commandNumber;
        }

        private int HandleConnect(Address receivedAddress, ref Peer result, Protocol.Connect command)
        {
            uint channelCount = command.ChannelCount;

            if (channelCount < MINIMUM_CHANNEL_COUNT || channelCount > MAXIMUM_CHANNEL_COUNT)
            {
                return -1;
            }

            foreach (var peer in Peers)
            {
                if (peer.State != PeerState.DISCONNECTED
                    && peer.Address.Host == receivedAddress.Host
                    && peer.Address.Port == receivedAddress.Port
                    && peer.SessionID == command.SessionID)
                {
                    return -1;
                }
            }

            var currentPeer = Array.Find(Peers, (peer) => peer.State == PeerState.DISCONNECTED);

            if (currentPeer == null)
            {
                return -1;
            }

            if (channelCount > ChannelLimit)
            {
                channelCount = ChannelLimit;
            }

            currentPeer.ResetChannels();
            currentPeer.ChannelCount = channelCount;
            currentPeer.State = PeerState.ACKNOWLEDGING_CONNECT;
            currentPeer.SessionID = command.SessionID;
            currentPeer.Address = receivedAddress;
            currentPeer.OutgoingPeerID = command.OutgoingPeerID;
            currentPeer.IncomingBandwidth = command.IncomingBandwidth;
            currentPeer.OutgoingBandwidth = command.OutgoingBandwidth;
            currentPeer.PacketThrottleInterval = command.PacketThrottleInterval;
            currentPeer.PacketThrottleAcceleration = command.PacketThrottleAcceleration;
            currentPeer.PacketThrottleDeceleration = command.PacketThrottleDeceleration;
            currentPeer.MTU = Utils.Clamp(command.MTU, MINIMUM_MTU, MAXIMUM_MTU);

            if (OutgoingBandwidth == 0
                && currentPeer.IncomingBandwidth == 0)
            {
                currentPeer.WindowSize = MAXIMUM_WINDOW_SIZE;
            }
            else if (OutgoingBandwidth == 0 
                || currentPeer.IncomingBandwidth == 0)
            {
                currentPeer.WindowSize = (Math.Max(OutgoingBandwidth, currentPeer.IncomingBandwidth) / Peer.WINDOW_SIZE_SCALE) * MINIMUM_WINDOW_SIZE;
            }
            else
            {
                currentPeer.WindowSize = (Math.Min(OutgoingBandwidth, currentPeer.IncomingBandwidth) / Peer.WINDOW_SIZE_SCALE) * MINIMUM_WINDOW_SIZE;
            }

            currentPeer.WindowSize = Utils.Clamp(currentPeer.WindowSize, MINIMUM_WINDOW_SIZE, MAXIMUM_WINDOW_SIZE);

            uint windowSize = IncomingBandwidth == 0 ? MAXIMUM_WINDOW_SIZE : (IncomingBandwidth / Peer.WINDOW_SIZE_SCALE) * MINIMUM_WINDOW_SIZE;

            if (windowSize > command.WindowSize)
            {
                windowSize = command.WindowSize;
            }

            windowSize = Utils.Clamp(windowSize, MINIMUM_WINDOW_SIZE, MAXIMUM_WINDOW_SIZE);

            var verifyCommand = new Protocol.VerifyConnect
            {
                Flags = ProtocolFlag.ACKNOWLEDGE,
                ChannelID = 0xFF,
                OutgoingPeerID = currentPeer.IncomingPeerID,
                MTU = currentPeer.MTU,
                WindowSize = windowSize,
                ChannelCount = channelCount,
                IncomingBandwidth = IncomingBandwidth,
                OutgoingBandwidth = OutgoingBandwidth,
                PacketThrottleInterval = currentPeer.PacketThrottleInterval,
                PacketThrottleAcceleration = currentPeer.PacketThrottleAcceleration,
                PacketThrottleDeceleration = currentPeer.PacketThrottleDeceleration,
            };

            currentPeer.QueueOutgoingCommand(verifyCommand, null, 0, 0);

            result = currentPeer;
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

            var packet = new Packet(command.DataLength, PacketFlags.RELIABLE);
            buffer.ReadBytes(packet.Data, 0, command.DataLength);

            if (peer.QueueIncomingCommand(command, packet, 0) == null)
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

            uint unsequencedGroup = command.UnsequencedGroup;
            uint index = unsequencedGroup % Peer.UNSEQUENCED_WINDOW_SIZE;

            if (unsequencedGroup < peer.IncomingUnsequencedGroup)
            {
                unsequencedGroup += 0x10000u;
            }

            if (unsequencedGroup >= (uint)peer.IncomingUnsequencedGroup + Peer.FREE_UNSEQUENCED_WINDOWS * Peer.UNSEQUENCED_WINDOW_SIZE)
            {
                return 0;
            }

            unsequencedGroup &= 0xFFFFu;

            if (unsequencedGroup - index != peer.IncomingUnsequencedGroup)
            {
                peer.IncomingUnsequencedGroup = (ushort)(unsequencedGroup - index);
                
                peer.UnsequencedWindow.SetAll(false);
            }
            else if (peer.UnsequencedWindow[(int)index])
            {
                return 0;
            }

            var packet = new Packet(command.DataLength, PacketFlags.UNSEQUENCED);
            buffer.ReadBytes(packet.Data, 0, command.DataLength);

            if (peer.QueueIncomingCommand(command, packet, 0) == null)
            {
                return -1;
            }

            peer.UnsequencedWindow[(int)index] = true;

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

            var packet = new Packet(command.DataLength, PacketFlags.NONE);
            buffer.ReadBytes(packet.Data, 0, packet.DataLength);

            if (peer.QueueIncomingCommand(command, packet, 0) == null)
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

            uint fragmentLength = command.DataLength;
            var channel = peer.Channels[command.ChannelID];
            uint startSequenceNumber = command.StartSequenceNumber;
            ushort startWindow = (ushort)(startSequenceNumber / Peer.RELIABLE_WINDOW_SIZE);
            ushort currentWindow = (ushort)(channel.IncomingReliableSequenceNumber / Peer.RELIABLE_WINDOW_SIZE);

            if (startSequenceNumber < channel.IncomingReliableSequenceNumber)
            {
                startWindow += Peer.RELIABLE_WINDOWS;
            }

            if (startWindow < currentWindow || startWindow >= currentWindow + Peer.FREE_RELIABLE_WINDOWS - 1)
            {
                return 0;
            }

            uint fragmentNumber = command.FragmentNumber;
            uint fragmentCount = command.FragmentCount;
            uint fragmentOffset = command.FragmentOffset;
            uint totalLength = command.TotalLength;

            if (fragmentOffset >= totalLength
                || fragmentOffset + fragmentLength > totalLength
                || fragmentNumber >= fragmentCount)
            {
                return -1;
            }


            IncomingCommand startCommand = null;
            for (var currentCommand = channel.IncomingReliableCommands.End.Prev;
                 currentCommand != channel.IncomingReliableCommands.End;
                 currentCommand = currentCommand.Prev)
            {
                var incomingCommand = currentCommand.Value;

                if (startSequenceNumber >= channel.IncomingReliableSequenceNumber)
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

                if (incomingCommand.ReliableSequenceNumber <= startSequenceNumber)
                {
                    if (incomingCommand.ReliableSequenceNumber < startSequenceNumber)
                    {
                        break;
                    }

                    if (!(incomingCommand.Command is Protocol.Send.Fragment)
                        || totalLength != incomingCommand.Packet.DataLength
                        || fragmentCount != incomingCommand.FragmentCount)
                    {

                        return -1;
                    }

                    startCommand = incomingCommand;
                    break;
                }
            }

            if (startCommand == null)
            {
                var packet = new Packet(totalLength, PacketFlags.RELIABLE);
                var hostCommand = command;

                hostCommand.ReliableSequenceNumber = (ushort)startSequenceNumber;
                hostCommand.StartSequenceNumber = (ushort)startSequenceNumber;
                hostCommand.DataLength = (ushort)fragmentLength;
                hostCommand.FragmentNumber = fragmentNumber;
                hostCommand.FragmentCount = fragmentCount;
                hostCommand.FragmentOffset = fragmentOffset;
                hostCommand.TotalLength = totalLength;

                startCommand = peer.QueueIncomingCommand(hostCommand, packet, fragmentCount);
            }

            if (!startCommand.Fragments[(int)fragmentNumber])
            {
                startCommand.FragmentsRemaining--;

                startCommand.Fragments[(int)fragmentNumber] = true;

                if (fragmentOffset + fragmentLength > startCommand.Packet.DataLength)
                {
                    fragmentLength = startCommand.Packet.DataLength - fragmentOffset;
                }

                buffer.ReadBytes(startCommand.Packet.Data, fragmentOffset, fragmentLength);

                if (startCommand.FragmentsRemaining <= 0)
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

            if (peer.IncomingBandwidth == 0u && OutgoingBandwidth == 0u)
            {
                peer.WindowSize = MAXIMUM_WINDOW_SIZE;
            }
            else
            {
                peer.WindowSize = (Math.Min(peer.IncomingBandwidth, OutgoingBandwidth) / Peer.WINDOW_SIZE_SCALE) * MINIMUM_WINDOW_SIZE;
            }

            peer.WindowSize = Utils.Clamp(peer.WindowSize, MINIMUM_WINDOW_SIZE, MAXIMUM_WINDOW_SIZE);
            
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

            if ((receivedSentTime & 0x8000u) > (ServiceTime & 0x8000u))
            {
                receivedSentTime -= 0x10000u;
            }

            if (Utils.TimeLess(ServiceTime, receivedSentTime))
            {
                return 0;
            }

            peer.LastReceiveTime = ServiceTime;
            peer.EarliestTimeout = 0;

            uint roundTripTime = Utils.TimeDiff(ServiceTime, receivedSentTime);

            peer.Throttle(roundTripTime);

            peer.RoundTripTimeVariance -= peer.RoundTripTimeVariance / 4u;

            if (roundTripTime >= peer.RoundTripTime)
            {
                peer.RoundTripTime += (roundTripTime - peer.RoundTripTime) / 8u;
                peer.RoundTripTimeVariance += (roundTripTime - peer.RoundTripTime) / 4u;
            }
            else
            {
                peer.RoundTripTime -= (peer.RoundTripTime - roundTripTime) / 8u;
                peer.RoundTripTimeVariance += (peer.RoundTripTime - roundTripTime) / 4u;
            }

            if (peer.RoundTripTime < peer.LowestRoundTripTime)
            {
                peer.LowestRoundTripTime = peer.RoundTripTime;
            }

            if (peer.RoundTripTimeVariance > peer.HighestRoundTripTimeVariance)
            {
                peer.HighestRoundTripTimeVariance = peer.RoundTripTimeVariance;
            }

            if (peer.PacketThrottleEpoch == 0
                || Utils.TimeDiff(ServiceTime, peer.PacketThrottleEpoch) >= peer.PacketThrottleInterval)
            {
                peer.LastRoundTripTime = peer.LowestRoundTripTime;
                peer.LastRoundTripTimeVariance = peer.HighestRoundTripTimeVariance;
                peer.LowestRoundTripTime = peer.RoundTripTime;
                peer.HighestRoundTripTimeVariance = peer.RoundTripTimeVariance;
                peer.PacketThrottleEpoch = ServiceTime;
            }

            uint receivedReliableSequenceNumber = command.ReceivedReliableSequenceNumber;

            var commandNumber = RemoveSentReliableCommand(peer, (ushort)receivedReliableSequenceNumber, command.ChannelID);

            switch (peer.State)
            {
                case PeerState.ACKNOWLEDGING_CONNECT:
                    if (commandNumber != ProtocolCommand.VERIFY_CONNECT)
                    {
                        return -1;
                    }

                    NotifyConnect(peer, evnt);
                    break;

                case PeerState.DISCONNECTING:
                    if (commandNumber != ProtocolCommand.DISCONNECT)
                    {
                        return -1;
                    }

                    NotifyDisconnect(peer, evnt);
                    break;

                case PeerState.DISCONNECT_LATER:
                    if (peer.OutgoingReliableCommands.Empty 
                        && peer.OutgoingUnreliableCommands.Empty
                        && peer.SentReliableCommands.Empty)
                    {
                        peer.Disconnect(peer.DisconnectData);
                    }
                    break;

                default:
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
            
            if (channelCount < MINIMUM_CHANNEL_COUNT || channelCount > MAXIMUM_CHANNEL_COUNT
                || command.PacketThrottleInterval != peer.PacketThrottleInterval
                || command.PacketThrottleAcceleration != peer.PacketThrottleAcceleration
                || command.PacketThrottleDeceleration != peer.PacketThrottleDeceleration)
            {
                DispatchState(peer, PeerState.ZOMBIE);
                return -1;
            }

            RemoveSentReliableCommand(peer, 1, 0xFF);

            if (channelCount < peer.ChannelCount)
            {
                peer.ChannelCount = channelCount;
            }

            peer.OutgoingPeerID = command.OutgoingPeerID;

            ushort mtu = Utils.Clamp(command.MTU, MINIMUM_MTU, MAXIMUM_MTU);
            
            if (mtu < peer.MTU)
            {
                peer.MTU = mtu;
            }

            uint windowSize = Utils.Clamp(command.WindowSize, MINIMUM_WINDOW_SIZE, MAXIMUM_WINDOW_SIZE);
            
            if (windowSize < peer.WindowSize)
            {
                peer.WindowSize = windowSize;
            }

            peer.IncomingBandwidth = command.IncomingBandwidth;
            peer.OutgoingBandwidth = command.OutgoingBandwidth;

            NotifyConnect(peer, evnt);
            
            return 0;
        }

        private int HandleIncomingCommands(Event evnt, Address receivedAddress, Buffer buffer)
        {
            uint receivedDataLength = buffer.DataLength;

            var header = ProtocolHeader.Create(buffer, Version);

            if (header == null)
            {
                return 0;
            }

            ushort peerID = header.PeerID;
            Peer peer = null;

            if (peerID != Version.MaxPeerID)
            {
                if (peerID > PeerCount)
                {
                    return 0;
                }

                peer = Peers[peerID];

                if (peer.State == PeerState.DISCONNECTED 
                    || peer.State == PeerState.ZOMBIE)
                {
                    return 0;
                }

                if ((receivedAddress.Host != peer.Address.Host
                    || receivedAddress.Port != peer.Address.Port)
                        && peer.Address.Host != Address.Broadcast)
                {
                    return 0;
                }

                if (header.SessionID != peer.SessionID)
                {
                    return 0;
                }

                peer.Address = receivedAddress;
                peer.IncomingDataTotal += receivedDataLength;
            }

            while (buffer.BytesLeft > 0)
            {
                var command = Protocol.Create(buffer, Version);

                if (command == null || command is Protocol.None)
                {
                    break;
                }

                if (peer == null && !(command is Protocol.Connect))
                {
                    break;
                }

                int result;
                switch (command)
                {
                    case Protocol.Acknowledge c: result = HandleAcknowledge(evnt, peer, c); break;
                    case Protocol.Connect c: result = HandleConnect(receivedAddress, ref peer, c); break;
                    case Protocol.VerifyConnect c: result = HandleVerifyConnect(evnt, peer, c); break;
                    case Protocol.Disconnect c: result = HandleDisconnect(peer, c); break;
                    case Protocol.Ping _: result = 0; break;
                    case Protocol.Send.Reliable c: result = HandleSendReliable(peer, c, buffer); break;
                    case Protocol.Send.Unreliable c: result = HandleSendUnreliable(peer, c, buffer); break;
                    case Protocol.Send.Unsequenced c: result = HandleSendUnsequenced(peer, c, buffer); break;
                    case Protocol.Send.Fragment c: result = HandleSendFragment(peer, c, buffer); break;
                    case Protocol.BandwidthLimit c: result = HandleBandwidthLimit(peer, c); break;
                    case Protocol.ThrottleConfigure c: result = HandleThrottleConfigure(peer, c); break;
                    default: result = -1; break;
                };

                if (result != 0)
                {
                    break;
                }

                if (peer != null && command.Flags.HasFlag(ProtocolFlag.ACKNOWLEDGE))
                {
                    if (header.TimeSent is ushort sentTime)
                    {
                        switch (peer.State)
                        {
                            case PeerState.DISCONNECTING:
                            case PeerState.ACKNOWLEDGING_CONNECT:
                                break;

                            case PeerState.ACKNOWLEDGING_DISCONNECT:
                                if (command is Protocol.Disconnect)
                                {
                                    peer.QueueAcknowledgement(command, sentTime);
                                }
                                break;

                            default:
                                peer.QueueAcknowledgement(command, sentTime);
                                break;
                        }
                    }
                    else
                    {
                        break;
                    }
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
            var buffer = new Buffer(MAXIMUM_MTU);
            for (; ; )
            {
                var receivedAddress = new Address(Address.Any, 0);
                var length = Socket.ReceiveFrom(ref receivedAddress, buffer);

                if (length < 0)
                {
                    return -1;
                }

                if (length == 0)
                {
                    return 0;
                }

                buffer.DataLength = (uint)length;
                TotalReceivedData += (uint)length;
                TotalReceivedPackets++;

                switch (HandleIncomingCommands(evnt, receivedAddress, buffer))
                {
                    case 1:
                        return 1;
                    case -1:
                        return -1;
                    default:
                        break;
                }
            }
        }

        private void SendAcknowledgements(Peer peer, Buffer buffer, ref bool continueSending) 
        {
            var currentAcknowledgement = peer.Acknowledgements.Begin;
            while (currentAcknowledgement != peer.Acknowledgements.End)
            {
                if (Protocol.Acknowledge.SIZE > buffer.BytesLeft)
                {
                    continueSending = true;

                    break;
                }

                var acknowledgement = currentAcknowledgement.Value;
                
                currentAcknowledgement = currentAcknowledgement.Next;

                var command = new Protocol.Acknowledge
                {
                    ChannelID = acknowledgement.Command.ChannelID,
                    ReceivedReliableSequenceNumber = acknowledgement.Command.ReliableSequenceNumber,
                    ReceivedSentTime = (ushort)acknowledgement.SentTime,
                };

                command.Write(buffer, Version);

                if (acknowledgement.Command is Protocol.Disconnect)
                {
                    DispatchState(peer, PeerState.ZOMBIE);
                }

                acknowledgement.Node.Remove();
            }
        }

        private void SendUnreliableOutgoingCommands(Peer peer, Buffer buffer, ref bool continueSending) 
        {
            var currentCommand = peer.OutgoingUnreliableCommands.Begin;
            
            while (currentCommand != peer.OutgoingUnreliableCommands.End)
            {
                var outgoingCommand = currentCommand.Value;
                uint commandSize = outgoingCommand.Command.Size;

                if(outgoingCommand.Packet != null)
                {
                    commandSize += outgoingCommand.Packet.DataLength;
                }

                if(commandSize > buffer.BytesLeft)
                {
                    continueSending = true;

                    break;
                }

                currentCommand = currentCommand.Next;

                if(outgoingCommand.Packet != null)
                {
                    peer.PacketThrottleCounter += Peer.PACKET_THROTTLE_COUNTER;
                    peer.PacketThrottleCounter %= Peer.PACKET_THROTTLE_SCALE;
                   
                    if(peer.PacketThrottleCounter > peer.PacketThrottle)
                    {
                        outgoingCommand.Node.Remove();
                        continue;
                    }
                }

                outgoingCommand.Command.Write(buffer, Version);
                outgoingCommand.Node.Remove();

                if(outgoingCommand.Packet != null)
                {
                    buffer.WriteBytes(outgoingCommand.Packet.Data);

                    peer.SentUnreliableCommands.End.Insert(outgoingCommand.Node);
                }
            }

            if (peer.State == PeerState.DISCONNECT_LATER
                && peer.OutgoingReliableCommands.Empty
                && peer.OutgoingUnreliableCommands.Empty
                && peer.SentReliableCommands.Empty)
            {
                peer.Disconnect(peer.DisconnectData);
            }
        }

        private int CheckTimeouts(Peer peer, Event evnt)
        {
            var currentCommand = peer.SentReliableCommands.Begin;
            var insertPosition = peer.OutgoingReliableCommands.Begin;

            while (currentCommand != peer.SentReliableCommands.End)
            {
                var outgoingCommand = currentCommand.Value;

                currentCommand = currentCommand.Next;

                if (Utils.TimeDiff(ServiceTime, outgoingCommand.SentTime) < outgoingCommand.RoundTripTimeout)
                {
                    continue;
                }

                if (peer.EarliestTimeout == 0
                    || Utils.TimeLess(outgoingCommand.SentTime, peer.EarliestTimeout))
                {
                    peer.EarliestTimeout = outgoingCommand.SentTime;
                }

                if (peer.EarliestTimeout != 0
                    && (Utils.TimeDiff(ServiceTime, peer.EarliestTimeout) >= Peer.TIMEOUT_MAXIMUM
                        || (outgoingCommand.RoundTripTimeout >= outgoingCommand.RoundTripTimeoutLimit
                            && Utils.TimeDiff(ServiceTime, peer.EarliestTimeout) >= Peer.TIMEOUT_MINIMUM)))
                {
                    NotifyDisconnect(peer, evnt);

                    return 1;
                }

                if (outgoingCommand.Packet != null)
                {
                    peer.ReliableDataInTransit -= outgoingCommand.FragmentLength;
                }

                peer.PacketsLost++;

                outgoingCommand.RoundTripTimeout *= 2;

                insertPosition.Insert(outgoingCommand.Node.Remove());

                // CHECKME: what does this do exactly? checks if we removed first command ???
                if (currentCommand == peer.SentReliableCommands.Begin
                    && !peer.SentReliableCommands.Empty)
                {
                    outgoingCommand = currentCommand.Value;

                    peer.NextTimeout = outgoingCommand.SentTime + outgoingCommand.RoundTripTimeout;
                }
            }

            return 0;
        }

        private void SendReliableOutgoingCommands(Peer peer, Buffer buffer, ref bool continueSending, ref bool hasSentTime)
        {
            var currentCommand = peer.OutgoingReliableCommands.Begin;
            
            while(currentCommand != peer.OutgoingReliableCommands.End)
            {
                var outgoingCommand = currentCommand.Value;

                var channel = outgoingCommand.Command.ChannelID < peer.ChannelCount ? peer.Channels[outgoingCommand.Command.ChannelID] : null;
                ushort reliableWindow = (ushort)(outgoingCommand.ReliableSequenceNumber / Peer.RELIABLE_WINDOW_SIZE);

                if(channel !=null 
                    && outgoingCommand.SendAttempts < 1
                    && (outgoingCommand.ReliableSequenceNumber % Peer.RELIABLE_WINDOW_SIZE) == 0)
                {
                    if (channel.ReliableWindows[(reliableWindow + Peer.RELIABLE_WINDOWS - 1) % Peer.RELIABLE_WINDOWS] >= Peer.RELIABLE_WINDOW_SIZE
                        || (channel.UsedReliableWindows & ((Peer.FREE_RELIABLE_WINDOWS_MASK << reliableWindow) 
                            | (Peer.FREE_RELIABLE_WINDOWS_MASK >> (Peer.RELIABLE_WINDOW_SIZE - reliableWindow)))) != 0u)
                    {
                        break;
                    }
                }

                uint commandSize = outgoingCommand.Command.Size;

                if (commandSize > buffer.BytesLeft)
                {
                    continueSending = true;
                    break;
                }

                if(outgoingCommand.Packet != null)
                {
                    uint windowSize = (peer.PacketThrottle * peer.WindowSize) / Peer.PACKET_THROTTLE_SCALE;

                    if(peer.ReliableDataInTransit + outgoingCommand.FragmentLength > Math.Max(windowSize, peer.MTU))
                    {
                        break;
                    }

                    if((ushort)(commandSize + outgoingCommand.FragmentLength) > (ushort)buffer.BytesLeft)
                    {
                        continueSending = true;

                        break;
                    }
                }

                currentCommand = currentCommand.Next;

                if(channel != null && outgoingCommand.SendAttempts < 1)
                {
                    channel.UsedReliableWindows |= (ushort)(1u << reliableWindow);
                    channel.ReliableWindows[reliableWindow]++;
                }

                outgoingCommand.SendAttempts++;

                if(outgoingCommand.RoundTripTimeout == 0)
                {
                    outgoingCommand.RoundTripTimeout = peer.RoundTripTime + 4u * peer.RoundTripTimeVariance;
                    outgoingCommand.RoundTripTimeoutLimit = Peer.TIMEOUT_LIMIT * outgoingCommand.RoundTripTimeout;
                }

                if(peer.SentReliableCommands.Empty)
                {
                    peer.NextTimeout = ServiceTime + outgoingCommand.RoundTripTimeout;
                }

                peer.SentReliableCommands.End.Insert(outgoingCommand.Node.Remove());
                
                outgoingCommand.SentTime = ServiceTime;

                var command = outgoingCommand.Command;
                hasSentTime = true;
                command.Write(buffer, Version);

                if(outgoingCommand.Packet != null)
                {
                    buffer.WriteBytes(outgoingCommand.Packet.Data, outgoingCommand.FragmentOffset, outgoingCommand.FragmentLength);
                    
                    peer.ReliableDataInTransit += outgoingCommand.FragmentLength;
                }

                peer.PacketsSent++;
            }
        }

        private int SendOutgoingCommands(Event evnt, bool checkForTimeout)
        {

            var buffer = new Buffer(MAXIMUM_MTU);

            bool continueSending = true;


            while (continueSending)
            {
                continueSending = false;

                foreach (var currentPeer in Peers)
                {
                    if (currentPeer.State == PeerState.DISCONNECTED || currentPeer.State == PeerState.ZOMBIE)
                    {
                        continue;
                    }

                    bool hasSentTime = false;
                    buffer.Position = Version.MaxHeaderSizeSend;
                    buffer.DataLength = currentPeer.MTU;

                    if (!currentPeer.Acknowledgements.Empty)
                    {
                        SendAcknowledgements(currentPeer, buffer, ref continueSending);
                    }

                    if (checkForTimeout
                        && !currentPeer.SentReliableCommands.Empty
                        && !Utils.TimeLess(ServiceTime, currentPeer.NextTimeout))
                    {
                        if (CheckTimeouts(currentPeer, evnt) == 1)
                        {
                            return 1;
                        }
                    }

                    if (!currentPeer.OutgoingReliableCommands.Empty)
                    {
                        SendReliableOutgoingCommands(currentPeer, buffer, ref continueSending, ref hasSentTime);
                    }
                    else if (currentPeer.SentReliableCommands.Empty
                        && Utils.TimeDiff(ServiceTime, currentPeer.LastReceiveTime) >= Peer.PING_INTERVAL)
                    {
                        if (Protocol.Ping.SIZE <= buffer.BytesLeft)
                        {
                            currentPeer.Ping();
                            SendReliableOutgoingCommands(currentPeer, buffer, ref continueSending, ref hasSentTime);
                        }
                    }

                    if (!currentPeer.OutgoingUnreliableCommands.Empty)
                    {
                        SendUnreliableOutgoingCommands(currentPeer, buffer, ref continueSending);
                    }

                    if (buffer.Position <= Version.MaxHeaderSizeSend)
                    {
                        continue;
                    }

                    if (currentPeer.PacketLossEpoch == 0u)
                    {
                        currentPeer.PacketLossEpoch = ServiceTime;
                    }
                    else if (Utils.TimeDiff(ServiceTime, currentPeer.PacketLossEpoch) >= Version.PacketLossInterval
                        && currentPeer.PacketsSent > 0u)
                    {
                        uint packetLoss = currentPeer.PacketsLost * Peer.PACKET_LOSS_SCALE / currentPeer.PacketsSent;

                        currentPeer.PacketLossVariance -= currentPeer.PacketLossVariance / 4u;

                        if (packetLoss >= currentPeer.PacketLoss)
                        {
                            currentPeer.PacketLoss += (packetLoss - currentPeer.PacketLoss) / 8u;
                            currentPeer.PacketLossVariance += (packetLoss - currentPeer.PacketLoss) / 4u;
                        }
                        else
                        {
                            currentPeer.PacketLoss -= (currentPeer.PacketLoss - packetLoss) / 8u;
                            currentPeer.PacketLossVariance += (currentPeer.PacketLoss - packetLoss) / 4u;
                        }

                        currentPeer.PacketLossEpoch = ServiceTime;
                        currentPeer.PacketsSent = 0;
                        currentPeer.PacketsLost = 0;
                    }


                    uint bufferLength = buffer.Position;
                    uint bufferOffset = 0;

                    var header = new ProtocolHeader
                    {
                        SessionID = currentPeer.SessionID,
                        PeerID = currentPeer.OutgoingPeerID,
                    };
                    if (hasSentTime)
                    {
                        header.TimeSent = (ushort)ServiceTime;
                    }
                    else
                    {
                        header.TimeSent = null;
                        bufferOffset += 2;
                        bufferLength -= 2;
                    }
                    buffer.Position = bufferOffset;
                    header.Write(buffer, Version);

                    currentPeer.LastSendTime = ServiceTime;

                    int sentLength = Socket.SendTo(currentPeer.Address, buffer.Data, bufferOffset, bufferLength);

                    RemoveSentUnreliableCommands(currentPeer);

                    if (sentLength < 0)
                    {
                        return -1;
                    }

                    TotalSentData += (uint)sentLength;
                    TotalSentPackets++;
                }
            }

            return 0;
        }

        /* Public API */

        public void Flush()
        {
            ServiceTime = GetTime();

            SendOutgoingCommands(null, false);
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
            else
            {
                return -1;
            }
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
                    default:
                        break;
                }
            }

            ServiceTime = GetTime();

            timeout += ServiceTime;

            bool waitCondition;

            do
            {
                if (Utils.TimeDiff(ServiceTime, BandwidthThrottleEpoch) >= Version.BandwidthThrottleInterval)
                {
                    BandwidthThrottle();
                }

                switch (SendOutgoingCommands(evnt, true))
                {
                    case 1:
                        return 1;
                    case -1:
                        return -1;
                    default:
                        break;
                }

                switch (ReceiveIncomingCommands(evnt))
                {
                    case 1:
                        return 1;
                    case -1:
                        return -1;
                    default:
                        break;
                }

                switch (SendOutgoingCommands(evnt, true))
                {
                    case 1:
                        return 1;
                    case -1:
                        return -1;
                    default:
                        break;
                }

                if (evnt != null)
                {
                    switch (DispatchIncomingCommands(evnt))
                    {
                        case 1:
                            return 1;
                        case -1:
                            return -1;
                        default:
                            break;
                    }
                }

                ServiceTime = GetTime();

                if (!Utils.TimeLess(ServiceTime, timeout))
                {
                    return 0;
                }

                waitCondition = true;

                if(Socket.WaitReceive(ref waitCondition, Utils.TimeDiff(timeout, ServiceTime)) != 0)
                {
                    return -1;
                }

                ServiceTime = GetTime();

            } while (waitCondition);

            return 0;
        }
    }
}
