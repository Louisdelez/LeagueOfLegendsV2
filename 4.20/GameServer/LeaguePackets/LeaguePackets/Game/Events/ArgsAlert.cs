using System;

namespace LeaguePackets.Game.Events
{
    public class ArgsAlert : ArgsBase
    {
        public override void ReadArgs(ByteReader reader)
        {
            base.ReadArgs(reader);
            reader.ReadPad(4);
            reader.ReadPad(4);
        }
        public override void WriteArgs(ByteWriter writer)
        {
            base.WriteArgs(writer);
            writer.WritePad(4);
            writer.WritePad(4);
        }
    }
}
