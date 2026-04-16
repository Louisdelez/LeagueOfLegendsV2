import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
public class ReadCrcTable extends GhidraScript {
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        Address tableAddr = currentProgram.getAddressFactory().getAddress("141947e80");
        println("=== CRC TABLE at 141947e80 (first 16 entries) ===");
        for (int i = 0; i < 16; i++) {
            int val = mem.getInt(tableAddr.add(i * 4));
            // Standard CRC32 table entry 0 = 0x00000000
            // Standard CRC32 table entry 1 = 0x77073096
            // Standard CRC32 table entry 2 = 0xEE0E612C
            println(String.format("  [%3d] = 0x%08X", i, val));
        }
        // Check entry 0 and 1 against known CRC32 values
        int e0 = mem.getInt(tableAddr);
        int e1 = mem.getInt(tableAddr.add(4));
        println("\nEntry 0 = 0x" + String.format("%08X", e0) + (e0 == 0 ? " (standard CRC32)" : " (NON-STANDARD!)"));
        println("Entry 1 = 0x" + String.format("%08X", e1) + (e1 == 0x77073096 ? " (standard CRC32)" : " (NON-STANDARD! expected 0x77073096)"));
    }
}
