import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
public class Decomp57d4c0 extends GhidraScript {
    public void run() throws Exception {
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        Address addr = currentProgram.getAddressFactory().getAddress("14057d4c0");
        Function f = currentProgram.getFunctionManager().getFunctionAt(addr);
        println("=== FUN_14057d4c0 (batch framing parser) ===");
        DecompileResults r = d.decompileFunction(f, 120, monitor);
        if (r.decompileCompleted())
            for (String line : r.getDecompiledFunction().getC().split("\n"))
                println(line);
        d.dispose();
    }
}
