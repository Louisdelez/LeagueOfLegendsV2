import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class Decomp1D64F0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        Address addr = currentProgram.getAddressFactory().getAddress("1401d64f0");
        Function fn = currentProgram.getFunctionManager().getFunctionContaining(addr);
        if (fn == null) fn = currentProgram.getFunctionManager().getFunctionAt(addr);
        if (fn != null) {
            println("=== " + fn.getName() + " at " + fn.getEntryPoint() + " size=" + fn.getBody().getNumAddresses() + " ===");
            DecompileResults r = decomp.decompileFunction(fn, 300, monitor);
            if (r.decompileCompleted()) {
                String[] lines = r.getDecompiledFunction().getC().split("\n");
                println("Lines: " + lines.length);
                for (int i = 0; i < Math.min(100, lines.length); i++) println(lines[i]);
            }
        } else println("No function at 1401d64f0");
        println("=== DONE ===");
        decomp.dispose();
    }
}
