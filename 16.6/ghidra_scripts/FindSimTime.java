import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
public class FindSimTime extends GhidraScript {
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        // Search for "LocalSimTime" string
        byte[] p = "LocalSimTime".getBytes("UTF-8");
        Address addr = mem.findBytes(currentProgram.getMinAddress(), p, null, true, monitor);
        while (addr != null) {
            var refs = getReferencesTo(addr);
            var block = mem.getBlock(addr);
            println("LocalSimTime at " + addr + " (" + block.getName() + ") refs=" + refs.length);
            for (var ref : refs) {
                Function fn = getFunctionContaining(ref.getFromAddress());
                println("  " + ref.getFromAddress() + " in " + (fn != null ? fn.getName() + " at " + fn.getEntryPoint() : "?"));
            }
            addr = mem.findBytes(addr.add(1), p, null, true, monitor);
        }
        // Also search for "gameStarted" or "GameStarted"
        for (String pat : new String[]{"gameStarted", "GameStarted", "game_started", "InitTimeout", "ConnectTimeout"}) {
            byte[] p2 = pat.getBytes("UTF-8");
            addr = mem.findBytes(currentProgram.getMinAddress(), p2, null, true, monitor);
            if (addr != null) {
                println(pat + " at " + addr);
            }
        }
    }
}
