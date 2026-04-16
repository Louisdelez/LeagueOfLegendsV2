using System;

namespace LENet;

[Flags]
public enum PacketFlags
{
	NONE = 0,
	RELIABLE = 1,
	UNSEQUENCED = 2,
	NO_ALLOCATE = 4
}
