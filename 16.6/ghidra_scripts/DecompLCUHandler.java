import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
public class DecompLCUHandler extends GhidraScript {
    public void run() throws Exception {
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        
        // FUN_1406dbd00 - OnJsonApiEvent handler
        Address addr = currentProgram.getAddressFactory().getAddress("1406dbd00");
        Function fn = currentProgram.getFunctionManager().getFunctionAt(addr);
        if (fn != null) {
            println("=== " + fn.getName() + " at " + fn.getEntryPoint() + " size=" + fn.getBody().getNumAddresses() + " ===");
            DecompileResults r = d.decompileFunction(fn, 60, monitor);
            if (r.decompileCompleted()) {
                for (String line : r.getDecompiledFunction().getC().split("\n"))
                    println(line);
            }
        }
        d.dispose();
    }
}
