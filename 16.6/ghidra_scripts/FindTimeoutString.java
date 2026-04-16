import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
public class FindTimeoutString extends GhidraScript {
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        // Search for "Timeout waiting to connect to"
        byte[] pattern = "Timeout waiting".getBytes("UTF-8");
        Address addr = mem.findBytes(currentProgram.getMinAddress(), pattern, null, true, monitor);
        while (addr != null) {
            println("Found string at: " + addr);
            // Find xrefs to this address
            var refs = getReferencesTo(addr);
            for (var ref : refs) {
                println("  Referenced from: " + ref.getFromAddress() + " type=" + ref.getReferenceType());
            }
            addr = mem.findBytes(addr.add(1), pattern, null, true, monitor);
        }
    }
}
