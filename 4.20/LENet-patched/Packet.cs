using System;

namespace LENet
{
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
            }
            else
            {
                Data = new byte[data.Length];
                data.CopyTo(Data, 0);
            }
        }

        public Packet(uint length, PacketFlags flags)
        {
            Flags = flags;
            Data = new byte[length];
        }

        public int Resize(uint newSize)
        {
            var ndata = new byte[(int)newSize];
            Array.Copy(Data, 0, ndata, 0, Math.Min(newSize, Data.LongLength));
            Data = ndata;
            return 0;
        }
    }
}
