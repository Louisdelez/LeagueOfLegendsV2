using System;


namespace LENet
{
    [Flags]
    public enum ProtocolFlag : byte
    {
        ACKNOWLEDGE = (1 << 7),
        UNSEQUENCED = (1 << 6),
    }
}
