import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
public class FindLCUHandler extends GhidraScript {
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        String[] patterns = {"OnJsonApiEvent", "lol-gameflow", "gameflow_v1", "LCURemoting", 
                            "ClientWebSocket", "WebSocketTransport", "InProgress", 
                            "GameSession", "Multiplayer Session"};
        for (String pat : patterns) {
            byte[] p = pat.getBytes("UTF-8");
            Address addr = mem.findBytes(currentProgram.getMinAddress(), p, null, true, monitor);
            int count = 0;
            while (addr != null && count < 3) {
                var refs = getReferencesTo(addr);
                var block = mem.getBlock(addr);
                if (refs.length > 0) {
                    println(pat + " at " + addr + " (" + block.getName() + ") " + refs.length + " xrefs:");
                    for (var ref : refs) {
                        Function fn = getFunctionContaining(ref.getFromAddress());
                        println("  " + ref.getFromAddress() + " in " + (fn != null ? fn.getName() : "?"));
                    }
                } else if (block.getName().contains("rdata")) {
                    println(pat + " at " + addr + " (NO xrefs)");
                }
                addr = mem.findBytes(addr.add(1), p, null, true, monitor);
                count++;
            }
        }
    }
}
