import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
public class DecompFLOW extends GhidraScript {
    public void run() throws Exception {
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        // Function containing 0x1405fb981
        Address addr = currentProgram.getAddressFactory().getAddress("1405fb981");
        Function fn = getFunctionContaining(addr);
        if (fn != null) {
            println("=== " + fn.getName() + " at " + fn.getEntryPoint() + " (size=" + fn.getBody().getNumAddresses() + ") ===");
            DecompileResults r = d.decompileFunction(fn, 120, monitor);
            if (r.decompileCompleted()) {
                String code = r.getDecompiledFunction().getC();
                for (String line : code.split("\n")) {
                    // Filter for interesting lines
                    if (line.contains("FLOW") || line.contains("timeout") || line.contains("Timeout") ||
                        line.contains("connect") || line.contains("if (") || line.contains("while") ||
                        line.contains("FUN_") || line.contains("return") || line.contains("param_") ||
                        line.contains("DAT_") || line.contains("0x") || line.contains("state")) {
                        println(line);
                    }
                }
            }
        } else {
            println("Function not found at address");
        }
        d.dispose();
    }
}
