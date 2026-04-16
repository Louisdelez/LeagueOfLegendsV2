using System;

namespace LENet
{
    public sealed class Acknowledgement : LList<Acknowledgement>.Element
    {
        public uint SentTime { get; set; }
        public Protocol Command { get; set; }
    }
}
