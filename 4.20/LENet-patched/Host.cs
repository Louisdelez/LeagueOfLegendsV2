using System;
using System.Net;
using System.Net.Sockets;

namespace LENet
{
    public sealed partial class Host : IDisposable
    {
        public const uint RECEIVE_BUFFER_SIZE = 256 * 1024;
        public const uint SEND_BUFFER_SIZE = 256 * 1024;
        public const ushort DEFAULT_MTU = 996;
        public const ushort MINIMUM_MTU = 576;
        public const ushort MAXIMUM_MTU = 4096;
        public const ushort MINIMUM_WINDOW_SIZE = 4096;
        public const ushort MAXIMUM_WINDOW_SIZE = 32768;
        public const byte MINIMUM_CHANNEL_COUNT = 1;
        public const byte MAXIMUM_CHANNEL_COUNT = 255;
        public const byte MAXIMUM_PEER_ID = 0x7F;

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

        private uint _nextSessionID = 1;

        private readonly int _timeStart = Environment.TickCount;
        public uint GetTime() => (uint)(Environment.TickCount - _timeStart); 

        public Host(Version version, Address? address, uint peerCount, uint channelCount = 0, uint incomingBandwith = 0, uint outgoingBandwith = 0, ushort mtu = 0)
        {
            if(peerCount > version.MaxPeerID)
            {
                throw new ArgumentOutOfRangeException("peerCount");
            }

            channelCount = channelCount == 0 ? MAXIMUM_CHANNEL_COUNT : channelCount;
            channelCount = Utils.Clamp(channelCount, MINIMUM_CHANNEL_COUNT, MAXIMUM_CHANNEL_COUNT);

            mtu = mtu == 0 ? DEFAULT_MTU : mtu;
            mtu = Utils.Clamp(mtu, MINIMUM_MTU, MAXIMUM_MTU);

            Socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.IP);
            if(address is Address addr)
            {
                try
                {
                    Socket.Bind(new IPEndPoint(addr.Host, addr.Port));
                }
                catch (Exception error)
                {
                    Socket.Dispose();
                    throw error;
                }
            }
            Socket.Blocking = false;
            Socket.EnableBroadcast = true;
            Socket.ReceiveBufferSize = (int)RECEIVE_BUFFER_SIZE;
            Socket.SendBufferSize = (int)SEND_BUFFER_SIZE;

            Version = version;
            ChannelLimit = channelCount;
            IncomingBandwidth = incomingBandwith;
            OutgoingBandwidth = outgoingBandwith;
            MTU = mtu;
            Peers = new Peer[(int)peerCount];

            for (var i = 0; i < peerCount; i++)
            {
                Peers[i] = new Peer(this, (ushort)i);
            }
        }

        public void Dispose()
        {
            Socket.Dispose();
        }

        public Peer Connect(Address address, uint channelCount = 0)
        {
            channelCount = channelCount == 0 ? ChannelLimit : channelCount;
            channelCount = Utils.Clamp(channelCount, MINIMUM_CHANNEL_COUNT, ChannelLimit);

            var currentPeer = Array.Find(Peers, (p) => p.State == PeerState.DISCONNECTED);

            if(currentPeer == null)
            {
                return null;
            }

            currentPeer.ResetChannels();
            currentPeer.ChannelCount = channelCount;
            currentPeer.State = PeerState.CONNECTING;
            currentPeer.Address = address;
            currentPeer.SessionID = _nextSessionID++;

            if(Version.MaxPeerID == 0x7Fu)
            {
                currentPeer.SessionID &= 0xFFu;
            }
            
            if(OutgoingBandwidth == 0)
            {
                currentPeer.WindowSize = MAXIMUM_WINDOW_SIZE;
            } 
            else
            {
                currentPeer.WindowSize = (OutgoingBandwidth / Peer.WINDOW_SIZE_SCALE) * MINIMUM_WINDOW_SIZE;
            }
            currentPeer.WindowSize = Utils.Clamp(currentPeer.WindowSize, MINIMUM_WINDOW_SIZE, MAXIMUM_WINDOW_SIZE);
            
            var command = new Protocol.Connect
            {
                Flags = ProtocolFlag.ACKNOWLEDGE,
                ChannelID = 0xFF,
                OutgoingPeerID = currentPeer.IncomingPeerID,
                MTU = currentPeer.MTU,
                WindowSize = currentPeer.WindowSize,
                ChannelCount = channelCount,
                IncomingBandwidth = IncomingBandwidth,
                OutgoingBandwidth = OutgoingBandwidth,
                PacketThrottleInterval = currentPeer.PacketThrottleInterval,
                PacketThrottleAcceleration = currentPeer.PacketThrottleAcceleration,
                PacketThrottleDeceleration = currentPeer.PacketThrottleDeceleration,
                SessionID = currentPeer.SessionID,
            };
            
            currentPeer.QueueOutgoingCommand(command, null, 0, 0);

            return currentPeer;
        }

        public void SetChannelLimit(uint channelLimit)
        {
            if(channelLimit == 0)
            {
                channelLimit = MAXIMUM_CHANNEL_COUNT;
            }
            ChannelLimit = Utils.Clamp(channelLimit, MINIMUM_CHANNEL_COUNT, MAXIMUM_CHANNEL_COUNT);
        }

        public void Broadcast(byte channelID, Packet packet)
        {
            foreach(var currentPeer in Peers)
            {
                if(currentPeer.State != PeerState.CONNECTED)
                {
                    continue;
                }
                currentPeer.Send(channelID, packet);
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
            uint timeCurrent = GetTime();
            uint elapsedTime = timeCurrent - BandwidthThrottleEpoch;

            if(elapsedTime < Version.BandwidthThrottleInterval)
            {
                return;
            }

            uint peersTotal = 0;
            uint dataTotal = 0;
            foreach (var peer in Peers)
            {
                if(peer.State != PeerState.CONNECTED && peer.State != PeerState.DISCONNECT_LATER)
                {
                    continue;
                }
                peersTotal++;
                dataTotal += peer.OutgoingDataTotal;
            }

            if(peersTotal == 0)
            {
                return;
            }

            uint peersRemaining = peersTotal;
            bool needsAdjustment = true;
            
            uint bandwidth = OutgoingBandwidth == 0 ? ~0u : (OutgoingBandwidth * elapsedTime) / 1000u;
            
            uint throttle = 0;
            
            while (peersRemaining > 0 && needsAdjustment)
            {
                needsAdjustment = false;

                if(dataTotal < bandwidth)
                {
                    throttle = Peer.PACKET_THROTTLE_SCALE;
                }
                else
                {
                    throttle = (bandwidth * Peer.PACKET_THROTTLE_SCALE) / dataTotal;
                }

                foreach (var peer in Peers)
                {
                    uint peerBandwidth = 0;

                    if ((peer.State != PeerState.CONNECTED && peer.State != PeerState.DISCONNECT_LATER)
                        || peer.IncomingBandwidth == 0
                        || peer.OutgoingBandwidthThrottleEpoch == timeCurrent)
                    {
                        continue;
                    }

                    peerBandwidth = (peer.IncomingBandwidth * elapsedTime) / 1000;

                    if((throttle * peer.OutgoingDataTotal) / Peer.PACKET_THROTTLE_SCALE <= peerBandwidth)
                    {
                        continue;
                    }

                    peer.PacketThrottleLimit = (peerBandwidth * Peer.PACKET_THROTTLE_SCALE) / peer.OutgoingDataTotal;

                    if(peer.PacketThrottleLimit == 0)
                    {
                        peer.PacketThrottleLimit = 1;
                    }

                    if(peer.PacketThrottle > peer.PacketThrottleLimit)
                    {
                        peer.PacketThrottle = peer.PacketThrottleLimit;
                    }

                    peer.OutgoingBandwidthThrottleEpoch = timeCurrent;
                    
                    needsAdjustment = true;
                    peersRemaining--;
                    bandwidth -= peerBandwidth;
                    dataTotal -= peerBandwidth;
                }
            }

            if (peersRemaining > 0)
            {
                foreach (var peer in Peers)
                {
                    if ((peer.State != PeerState.CONNECTED && peer.State != PeerState.DISCONNECT_LATER)
                        || peer.OutgoingBandwidthThrottleEpoch == timeCurrent)
                    {
                        continue;
                    }

                    peer.PacketThrottleLimit = throttle;

                    if(peer.PacketThrottle > peer.PacketThrottleLimit)
                    {
                        peer.PacketThrottle = peer.PacketThrottleLimit;
                    }
                }
            }

            if(RecalculateBandwidthLimits)
            {
                RecalculateBandwidthLimits = false;

                peersRemaining = peersTotal;
                bandwidth = IncomingBandwidth;
                needsAdjustment = true;

                uint bandwidthLimit = 0;
                if (bandwidth != 0)
                {
                    while (peersRemaining > 0 && needsAdjustment)
                    {
                        needsAdjustment = false;
                        bandwidthLimit = bandwidth / peersRemaining;

                        foreach (var peer in Peers)
                        {
                            if ((peer.State != PeerState.CONNECTED && peer.State != PeerState.DISCONNECT_LATER) 
                                || peer.IncomingBandwidthThrottleEpoch == timeCurrent)
                            {
                                continue;
                            }

                            if (peer.OutgoingBandwidth > 0 
                                && peer.OutgoingBandwidth >= bandwidthLimit)
                            {
                                continue;
                            }

                            peer.IncomingBandwidthThrottleEpoch = timeCurrent;

                            needsAdjustment = true;
                            peersRemaining--;
                            bandwidth -= peer.OutgoingBandwidth;
                        }
                    }
                }

                foreach (var peer in Peers)
                {
                    if (peer.State != PeerState.CONNECTED && peer.State != PeerState.DISCONNECT_LATER)
                    {
                        continue;
                    }

                    var command = new Protocol.BandwidthLimit
                    {
                        Flags = ProtocolFlag.ACKNOWLEDGE,
                        ChannelID = 0xFF,
                        OutgoingBandwidth = OutgoingBandwidth,
                    };

                    if (peer.IncomingBandwidthThrottleEpoch == timeCurrent)
                    {
                        command.IncomingBandwidth = peer.OutgoingBandwidth;
                    }
                    else
                    {
                        command.IncomingBandwidth = bandwidthLimit;
                    }

                    peer.QueueOutgoingCommand(command, null, 0, 0);
                }
            }

            BandwidthThrottleEpoch = timeCurrent;

            foreach (var peer in Peers)
            {
                peer.IncomingDataTotal = 0;
                peer.OutgoingDataTotal = 0;
            }
        }
    }
}
