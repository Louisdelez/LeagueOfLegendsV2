using System;

namespace LENet
{
    public sealed class OutgoingCommand : LList<OutgoingCommand>.Element
    {
        public ushort ReliableSequenceNumber { get; set; }
        public ushort UnreliableSequenceNumber { get; set; }
        public uint SentTime { get; set; }
        public uint RoundTripTimeout { get; set; }
        public uint RoundTripTimeoutLimit { get; set; }
        public uint FragmentOffset { get; set; }
        public ushort FragmentLength { get; set; }
        public ushort SendAttempts { get; set; }
        public Protocol Command { get; set; }
        public Packet Packet { get; set; }
    }
}
