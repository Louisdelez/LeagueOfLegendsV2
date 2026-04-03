import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
public class SearchFLOW extends GhidraScript {
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        // Search for "FLOW" as a standalone string (might be referenced separately)
        byte[] p = "FLOW".getBytes("UTF-8");
        Address addr = mem.findBytes(currentProgram.getMinAddress(), p, null, true, monitor);
        int count = 0;
        while (addr != null && count < 20) {
            // Check if it's a standalone string (preceded/followed by null or space)
            byte prev = 0, next = 0;
            try { prev = mem.getByte(addr.subtract(1)); } catch (Exception e) {}
            try { next = mem.getByte(addr.add(4)); } catch (Exception e) {}
            if (prev == 0 || prev == ' ' || prev == '"' || prev == ':') {
                println("FLOW string at: " + addr + " (prev=0x" + String.format("%02X", prev) + " next=0x" + String.format("%02X", next) + ")");
                var refs = getReferencesTo(addr);
                if (refs.length > 0) {
                    for (var ref : refs) {
                        println("  Ref from: " + ref.getFromAddress());
                    }
                }
            }
            addr = mem.findBytes(addr.add(1), p, null, true, monitor);
            count++;
        }
    }
}
