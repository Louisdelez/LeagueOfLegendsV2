import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
public class FindTimer30 extends GhidraScript {
    public void run() throws Exception {
        // Search for 30000 (0x7530) as a 32-bit immediate in .rdata/.data
        Memory mem = currentProgram.getMemory();
        // Search .rdata for 30000 as little-endian int
        byte[] pattern = new byte[] {0x30, 0x75, 0x00, 0x00}; // 30000 LE
        Address addr = mem.findBytes(currentProgram.getMinAddress(), pattern, null, true, monitor);
        int count = 0;
        while (addr != null && count < 20) {
            var block = mem.getBlock(addr);
            if (block != null && (block.getName().contains("data") || block.getName().contains("rdata"))) {
                println("30000 at " + addr + " in " + block.getName());
                var refs = getReferencesTo(addr);
                for (var ref : refs) {
                    println("  ref from " + ref.getFromAddress());
                }
            }
            addr = mem.findBytes(addr.add(1), pattern, null, true, monitor);
            count++;
        }
        
        // Also search for 30.0f as IEEE 754 float (0x41F00000)
        pattern = new byte[] {0x00, 0x00, (byte)0xF0, 0x41};
        addr = mem.findBytes(currentProgram.getMinAddress(), pattern, null, true, monitor);
        count = 0;
        while (addr != null && count < 10) {
            var block = mem.getBlock(addr);
            if (block != null && (block.getName().contains("data") || block.getName().contains("rdata"))) {
                var refs = getReferencesTo(addr);
                if (refs.length > 0) {
                    println("30.0f at " + addr + " in " + block.getName() + " (" + refs.length + " refs)");
                    for (var ref : refs) {
                        Function fn = getFunctionContaining(ref.getFromAddress());
                        println("  ref from " + ref.getFromAddress() + 
                            (fn != null ? " in " + fn.getName() : ""));
                    }
                }
            }
            addr = mem.findBytes(addr.add(1), pattern, null, true, monitor);
            count++;
        }
    }
}
