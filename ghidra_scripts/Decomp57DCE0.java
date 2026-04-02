import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
public class Decomp57DCE0 extends GhidraScript {
    public void run() throws Exception {
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        Address a = currentProgram.getAddressFactory().getAddress("14057dce0");
        Function f = currentProgram.getFunctionManager().getFunctionContaining(a);
        if (f == null) f = currentProgram.getFunctionManager().getFunctionAt(a);
        if (f != null) {
            println("=== " + f.getName() + " at " + f.getEntryPoint() + " size=" + f.getBody().getNumAddresses() + " ===");
            DecompileResults r = d.decompileFunction(f, 300, monitor);
            if (r.decompileCompleted()) for (String l : r.getDecompiledFunction().getC().split("\n")) println(l);
        } else println("No function at 14057dce0");
        println("=== DONE ===");
        d.dispose();
    }
}
