using System;

namespace LENet
{
    public sealed class Version
    {
        public ushort MaxPeerID { get; }

        public uint ChecksumSizeSend { get; }

        public uint ChecksumSizeReceive { get; }

        public uint BandwidthThrottleInterval { get; }

        public uint PacketLossInterval { get; }

        private uint MaxHeaderSizeBase { get; }

        public uint MaxHeaderSizeSend => ChecksumSizeSend + MaxHeaderSizeBase;

        public uint MaxHeaderSizeReceive => ChecksumSizeReceive + MaxHeaderSizeBase;

        private Version(ushort maxPeerID, uint checksumSizeSend, uint checksumSizeReceive, uint maxHeaderSizeBase, uint bandwidthThrottleInterval, uint packetLossInterval)
        {
            MaxPeerID = maxPeerID;
            ChecksumSizeSend = checksumSizeSend;
            ChecksumSizeReceive = checksumSizeReceive;
            MaxHeaderSizeBase = maxHeaderSizeBase;
            BandwidthThrottleInterval = bandwidthThrottleInterval;
            PacketLossInterval = packetLossInterval;
        }

        public static Version Seasson12 { get; } = new Version(0x7FFF, 0, 0, 8, 1000, 10000);

        public static Version Seasson34 { get; } = new Version(0x7F, 0, 0, 4, 0xFFFFFFFF, 0xFFFFFFFF);

        public static Version Patch420 { get; } = new Version(0x7F, 4, 4, 4, 0xFFFFFFFF, 0xFFFFFFFF);

        public static Version Seasson8_Client { get; } = new Version(0x7F, 8, 0, 4, 0xFFFFFFFF, 0xFFFFFFFF);

        public static Version Seasson8_Server { get; } = new Version(0x7F, 0, 8, 4, 0xFFFFFFFF, 0xFFFFFFFF);

        public static Version Patch713 { get; } = new Version(0x7F, 8, 8, 4, 0xFFFFFFFF, 0xFFFFFFFF);
    }
}
