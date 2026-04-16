import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
public class DecompInProgress extends GhidraScript {
    public void run() throws Exception {
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        Address addr = currentProgram.getAddressFactory().getAddress("140728560");
        Function fn = currentProgram.getFunctionManager().getFunctionAt(addr);
        if (fn != null) {
            println("=== " + fn.getName() + " at " + fn.getEntryPoint() + " ===");
            DecompileResults r = d.decompileFunction(fn, 60, monitor);
            if (r.decompileCompleted()) {
                String code = r.getDecompiledFunction().getC();
                for (String line : code.split("\n")) {
                    if (line.contains("InProgress") || line.contains("FUN_14") || 
                        line.contains("param_") || line.contains("0x422") ||
                        line.contains("state") || line.contains("ready") ||
                        line.contains("connect") || line.contains("DAT_")) {
                        println(line);
                    }
                }
            }
        }
        d.dispose();
    }
}
