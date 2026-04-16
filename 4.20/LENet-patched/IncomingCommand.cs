using System;
using System.Collections;

namespace LENet
{
    public sealed class IncomingCommand : LList<IncomingCommand>.Element
    {
        public ushort ReliableSequenceNumber { get; set; }
        public ushort UnreliableSequenceNumber { get; set; }
        public Protocol Command { get; set; } = new Protocol.None();
        public uint FragmentCount { get; set; }
        public uint FragmentsRemaining { get; set; }
        public BitArray Fragments { get; set; } = new BitArray(0);
        public Packet Packet { get; set; } = null;

        public IncomingCommand() { }
    }
}
