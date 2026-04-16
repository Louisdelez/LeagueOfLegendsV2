namespace LENet
{
    public sealed class ProtocolHeader
    {
        public uint SessionID { get; set; } = 0;
        public ushort PeerID { get; set; } = 0;
        public ushort? TimeSent { get; set; } = null;

        public static ProtocolHeader Create(Buffer reader, Version version)
        {
            var result = new ProtocolHeader();

            if ((version.MaxHeaderSizeReceive - 2) > reader.BytesLeft)
            {
                return null;
            }

            reader.Position += version.ChecksumSizeReceive;

            bool hasSentTime = false;

            if(version.MaxPeerID > 0x7F)
            {
                result.SessionID = reader.ReadUInt32();
                ushort peerID = reader.ReadUInt16();
                if ((peerID & 0x8000u) != 0)
                {
                    hasSentTime = true;
                }
                result.PeerID = (ushort)(peerID & 0x7FFF);
            }
            else
            {
                result.SessionID = reader.ReadByte();
                byte peerID = reader.ReadByte();
                if ((peerID & 0x80) != 0)
                {
                    hasSentTime = true;
                }
                result.PeerID = (ushort)(peerID & 0x7F);
            }

            if (hasSentTime)
            {
                if(2 > reader.BytesLeft)
                {
                    return null;
                }

                result.TimeSent = reader.ReadUInt16();
            }

            return result;
        }

        public void Write(Buffer writer, Version version)
        {
            writer.Position += version.ChecksumSizeSend;

            if(version.MaxPeerID > 0x7F)
            {
                writer.WriteUInt32(SessionID);
                ushort peerID = (ushort)(PeerID | (TimeSent != null ? 0x8000u : 0u));
                writer.WriteUInt16(peerID);
            }
            else
            {
                writer.WriteByte((byte)SessionID);
                byte peerID = (byte)(PeerID | (TimeSent != null ? 0x80 : 0u));
                writer.WriteByte(peerID);
            }

            if (TimeSent != null)
            {
                writer.WriteUInt16((ushort)TimeSent);
            }
        }
    }
}
