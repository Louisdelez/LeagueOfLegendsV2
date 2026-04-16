namespace LENet;

public sealed class Channel
{
	public ushort OutgoingReliableSequenceNumber { get; set; }

	public ushort OutgoingUnreliableSequenceNumber { get; set; }

	public ushort UsedReliableWindows { get; set; }

	public ushort[] ReliableWindows { get; } = new ushort[16];

	public ushort IncomingReliableSequenceNumber { get; set; }

	public ushort IncomingUnreliableSequenceNumber { get; set; }

	public LList<IncomingCommand> IncomingReliableCommands { get; } = new LList<IncomingCommand>();

	public LList<IncomingCommand> IncomingUnreliableCommands { get; } = new LList<IncomingCommand>();
}
