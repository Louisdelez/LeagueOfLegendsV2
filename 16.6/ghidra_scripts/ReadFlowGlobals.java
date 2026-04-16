import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
public class ReadFlowGlobals extends GhidraScript {
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        // Read DAT_141da5228 - is it a pointer or direct value?
        Address dat1 = currentProgram.getAddressFactory().getAddress("141da5228");
        long val1 = mem.getLong(dat1);
        println("DAT_141da5228 = 0x" + Long.toHexString(val1));
        // If it's a pointer, read +8 from the pointed location
        // If it's direct, read at 141da5230
        Address dat1_8 = currentProgram.getAddressFactory().getAddress("141da5230");
        int val1_8 = mem.getInt(dat1_8);
        println("*(DAT_141da5228 + 8) direct = " + val1_8 + " (at 141da5230)");
        
        // Read DAT_141da1480
        Address dat2 = currentProgram.getAddressFactory().getAddress("141da1480");
        long val2 = mem.getLong(dat2);
        println("DAT_141da1480 = 0x" + Long.toHexString(val2));
        
        // Check if these are in .data or .bss
        var block1 = mem.getBlock(dat1);
        var block2 = mem.getBlock(dat2);
        println("DAT_141da5228 in block: " + (block1 != null ? block1.getName() : "unknown"));
        println("DAT_141da1480 in block: " + (block2 != null ? block2.getName() : "unknown"));
        
        // Read surrounding bytes for context
        byte[] ctx = new byte[32];
        mem.getBytes(dat1, ctx);
        StringBuilder sb = new StringBuilder();
        for (byte b : ctx) sb.append(String.format("%02X ", b & 0xFF));
        println("DAT_141da5228 bytes: " + sb.toString());
    }
}
