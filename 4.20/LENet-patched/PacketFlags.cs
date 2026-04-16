using System;

namespace LENet
{
    [Flags]
    public enum PacketFlags
    {
        NONE = 0,
        RELIABLE = (1 << 0),
        UNSEQUENCED = (1 << 1),
        NO_ALLOCATE = (1 << 2),
    }
}
