using System;

namespace LENet
{
    public sealed class Event
    {
        public EventType Type { get; set; }
        public Peer Peer { get; set; }
        public byte ChannelID { get; set; }
        public uint Data { get; set; }
        public Packet Packet { get; set; }

        public Event() { }
    }
}
