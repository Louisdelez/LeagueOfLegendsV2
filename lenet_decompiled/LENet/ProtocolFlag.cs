using System;

namespace LENet;

[Flags]
public enum ProtocolFlag : byte
{
	ACKNOWLEDGE = 0x80,
	UNSEQUENCED = 0x40
}
