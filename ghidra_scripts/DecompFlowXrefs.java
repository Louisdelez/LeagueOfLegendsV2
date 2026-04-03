import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
public class DecompFlowXrefs extends GhidraScript {
    public void run() throws Exception {
        // All unique functions that reference "FLOW" at 0x1419494B0
        long[] funcAddrs = {0x1405fb620L, 0x140643e7cL, 0x1406466b7L};
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        for (long fa : funcAddrs) {
            Address addr = currentProgram.getAddressFactory().getAddress(Long.toHexString(fa));
            Function fn = getFunctionContaining(addr);
            if (fn == null) continue;
            println("=== " + fn.getName() + " at " + fn.getEntryPoint() + " (xref at " + addr + ") ===");
            DecompileResults r = d.decompileFunction(fn, 60, monitor);
            if (r.decompileCompleted()) {
                String code = r.getDecompiledFunction().getC();
                for (String line : code.split("\n")) {
                    if (line.contains("FLOW") || line.contains("Timeout") || line.contains("timeout") ||
                        line.contains("connect") || line.contains("timer") || line.contains("30") ||
                        line.contains("0x1e") || line.contains("FUN_14") || 
                        line.contains("if (") || line.contains("return")) {
                        println("  " + line.trim());
                    }
                }
            }
            println("");
        }
        d.dispose();
    }
}
