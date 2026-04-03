import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
public class FindTimeoutFunc extends GhidraScript {
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        // Search for "Timeout waiting" bytes in .text (not .rdata) 
        // as it might be an inline string or constructed differently
        
        // Actually, search for the full "Timeout waiting to connect to: " in ALL sections
        byte[] p = "Timeout waiting to connect to".getBytes("UTF-8");
        Address addr = mem.findBytes(currentProgram.getMinAddress(), p, null, true, monitor);
        while (addr != null) {
            println("Found at: " + addr + " in block: " + mem.getBlock(addr).getName());
            // Try to find xrefs by searching for LEA references
            // The string address as 4-byte LE offset from nearby code
            long strOffset = addr.getOffset();
            // Search .text for any 4-byte value that could be a RIP-relative offset to this string
            Address textStart = currentProgram.getAddressFactory().getAddress("140001000");
            Address textEnd = currentProgram.getAddressFactory().getAddress("1411F0000");
            byte[] searchPattern = new byte[4];
            // Try searching for the lower 4 bytes of the address
            int low4 = (int)(strOffset & 0xFFFFFFFFL);
            searchPattern[0] = (byte)(low4 & 0xFF);
            searchPattern[1] = (byte)((low4 >> 8) & 0xFF);
            searchPattern[2] = (byte)((low4 >> 16) & 0xFF);
            searchPattern[3] = (byte)((low4 >> 24) & 0xFF);
            println("Searching for bytes: " + String.format("%02X %02X %02X %02X", 
                searchPattern[0]&0xFF, searchPattern[1]&0xFF, searchPattern[2]&0xFF, searchPattern[3]&0xFF));
            
            addr = mem.findBytes(addr.add(1), p, null, true, monitor);
        }
        
        // Also: search for the "connect to:" part (shorter, more matches)
        p = "connect to:".getBytes("UTF-8");
        addr = mem.findBytes(currentProgram.getMinAddress(), p, null, true, monitor);
        int count = 0;
        while (addr != null && count < 10) {
            var refs = getReferencesTo(addr);
            if (refs.length > 0) {
                println("'connect to:' at " + addr + " has " + refs.length + " xrefs:");
                for (var ref : refs) {
                    Function fn = getFunctionContaining(ref.getFromAddress());
                    println("  " + ref.getFromAddress() + " in " + (fn != null ? fn.getName() : "unknown"));
                }
            }
            addr = mem.findBytes(addr.add(1), p, null, true, monitor);
            count++;
        }
    }
}
