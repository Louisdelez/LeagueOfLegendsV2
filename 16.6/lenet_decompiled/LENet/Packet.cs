using System;

namespace LENet;

public sealed class Packet
{
	public PacketFlags Flags { get; set; }

	public byte[] Data { get; set; }

	public uint DataLength => (uint)Data.Length;

	public Packet(byte[] data, PacketFlags flags)
	{
		Flags = flags;
		if (flags.HasFlag(PacketFlags.NO_ALLOCATE))
		{
			Data = data;
			return;
		}
		Data = new byte[data.Length];
		data.CopyTo(Data, 0);
	}

	public Packet(uint length, PacketFlags flags)
	{
		Flags = flags;
		Data = new byte[length];
	}

	public int Resize(uint newSize)
	{
		byte[] array = new byte[newSize];
		Array.Copy(Data, 0L, array, 0L, Math.Min(newSize, Data.LongLength));
		Data = array;
		return 0;
	}
}
