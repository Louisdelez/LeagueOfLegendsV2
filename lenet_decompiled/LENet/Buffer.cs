using System;

namespace LENet;

public sealed class Buffer
{
	public byte[] Data { get; set; }

	public uint DataLength { get; set; }

	public uint Position { get; set; }

	public uint BytesLeft => DataLength - Position;

	public Buffer(uint length)
	{
		Data = new byte[length];
		DataLength = length;
	}

	public void WriteByte(byte val)
	{
		Data[Position++] = val;
	}

	public void WriteUInt16(ushort val)
	{
		Data[Position++] = (byte)((val >> 8) & 0xFF);
		Data[Position++] = (byte)(val & 0xFF);
	}

	public void WriteUInt32(uint val)
	{
		Data[Position++] = (byte)((val >> 24) & 0xFF);
		Data[Position++] = (byte)((val >> 16) & 0xFF);
		Data[Position++] = (byte)((val >> 8) & 0xFF);
		Data[Position++] = (byte)(val & 0xFF);
	}

	public void WriteBytes(byte[] source)
	{
		Array.Copy(source, 0, Data, (int)Position, source.Length);
		Position += (uint)source.Length;
	}

	public void WriteBytes(byte[] source, uint offset, uint length)
	{
		Array.Copy(source, (int)offset, Data, (int)Position, (int)length);
		Position += length;
	}

	public byte ReadByte()
	{
		return Data[Position++];
	}

	public ushort ReadUInt16()
	{
		ushort num = 0;
		num |= (ushort)(Data[Position++] << 8);
		return (ushort)(num | Data[Position++]);
	}

	public uint ReadUInt32()
	{
		uint num = 0u;
		num |= (uint)(Data[Position++] << 24);
		num |= (uint)(Data[Position++] << 16);
		num |= (uint)(Data[Position++] << 8);
		return num | Data[Position++];
	}

	public void ReadBytes(byte[] result, uint offset, uint length)
	{
		Array.Copy(Data, (int)Position, result, (int)offset, (int)length);
		Position += length;
	}
}
