namespace LENet;

public sealed class ProtocolHeader
{
	public uint SessionID { get; set; } = 0u;

	public ushort PeerID { get; set; } = 0;

	public ushort? TimeSent { get; set; } = null;

	public static ProtocolHeader Create(Buffer reader, Version version)
	{
		ProtocolHeader protocolHeader = new ProtocolHeader();
		if (version.MaxHeaderSizeReceive - 2 > reader.BytesLeft)
		{
			return null;
		}
		reader.Position += version.ChecksumSizeReceive;
		bool flag = false;
		if (version.MaxPeerID > 127)
		{
			protocolHeader.SessionID = reader.ReadUInt32();
			ushort num = reader.ReadUInt16();
			if ((num & 0x8000) != 0)
			{
				flag = true;
			}
			protocolHeader.PeerID = (ushort)(num & 0x7FFF);
		}
		else
		{
			protocolHeader.SessionID = reader.ReadByte();
			byte b = reader.ReadByte();
			if ((b & 0x80) != 0)
			{
				flag = true;
			}
			protocolHeader.PeerID = (ushort)(b & 0x7F);
		}
		if (flag)
		{
			if (2 > reader.BytesLeft)
			{
				return null;
			}
			protocolHeader.TimeSent = reader.ReadUInt16();
		}
		return protocolHeader;
	}

	public void Write(Buffer writer, Version version)
	{
		writer.Position += version.ChecksumSizeSend;
		if (version.MaxPeerID > 127)
		{
			writer.WriteUInt32(SessionID);
			ushort val = (ushort)(PeerID | (TimeSent.HasValue ? 32768 : 0));
			writer.WriteUInt16(val);
		}
		else
		{
			writer.WriteByte((byte)SessionID);
			byte val2 = (byte)(PeerID | (TimeSent.HasValue ? 128 : 0));
			writer.WriteByte(val2);
		}
		if (TimeSent.HasValue)
		{
			writer.WriteUInt16(TimeSent.Value);
		}
	}
}
