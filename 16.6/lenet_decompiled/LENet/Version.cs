namespace LENet;

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

	public static Version Seasson12 { get; } = new Version(32767, 0u, 0u, 8u, 1000u, 10000u);

	public static Version Seasson34 { get; } = new Version(127, 0u, 0u, 4u, uint.MaxValue, uint.MaxValue);

	public static Version Patch420 { get; } = new Version(127, 4u, 4u, 4u, uint.MaxValue, uint.MaxValue);

	public static Version Seasson8_Client { get; } = new Version(127, 8u, 0u, 4u, uint.MaxValue, uint.MaxValue);

	public static Version Seasson8_Server { get; } = new Version(127, 0u, 8u, 4u, uint.MaxValue, uint.MaxValue);

	private Version(ushort maxPeerID, uint checksumSizeSend, uint checksumSizeReceive, uint maxHeaderSizeBase, uint bandwidthThrottleInterval, uint packetLossInterval)
	{
		MaxPeerID = maxPeerID;
		ChecksumSizeSend = checksumSizeSend;
		ChecksumSizeReceive = checksumSizeReceive;
		MaxHeaderSizeBase = maxHeaderSizeBase;
		BandwidthThrottleInterval = bandwidthThrottleInterval;
		PacketLossInterval = packetLossInterval;
	}
}
