import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
public class Decomp168a4f0 extends GhidraScript {
    public void run() throws Exception {
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        Address a = currentProgram.getAddressFactory().getAddress("14168a4f0");
        Function f = currentProgram.getFunctionManager().getFunctionContaining(a);
        if (f == null) f = currentProgram.getFunctionManager().getFunctionAt(a);
        if (f != null) {
            println("=== " + f.getName() + " at " + f.getEntryPoint() + " size=" + f.getBody().getNumAddresses() + " ===");
            DecompileResults r = d.decompileFunction(f, 300, monitor);
            if (r.decompileCompleted()) {
                String[] lines = r.getDecompiledFunction().getC().split("\n");
                println("Lines: " + lines.length);
                for (int i = 0; i < Math.min(60, lines.length); i++) println(lines[i]);
            }
        } else println("No function at 14168a4f0");
        println("\n=== DONE ===");
        d.dispose();
    }
}
