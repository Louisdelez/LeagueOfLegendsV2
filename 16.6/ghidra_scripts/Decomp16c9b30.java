import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
public class Decomp16c9b30 extends GhidraScript {
    public void run() throws Exception {
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        Address a = currentProgram.getAddressFactory().getAddress("1416c9b30");
        Function f = currentProgram.getFunctionManager().getFunctionContaining(a);
        if (f == null) f = currentProgram.getFunctionManager().getFunctionAt(a);
        if (f != null) {
            println("=== " + f.getName() + " at " + f.getEntryPoint() + " size=" + f.getBody().getNumAddresses() + " ===");
            DecompileResults r = d.decompileFunction(f, 300, monitor);
            if (r.decompileCompleted()) {
                String[] lines = r.getDecompiledFunction().getC().split("\n");
                println("Lines: " + lines.length);
                for (String l : lines) println(l);
            }
        } else println("No function");
        println("\n=== DONE ===");
        d.dispose();
    }
}
