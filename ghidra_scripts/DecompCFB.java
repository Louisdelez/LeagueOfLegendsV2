import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
public class DecompCFB extends GhidraScript {
    public void run() throws Exception {
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        // FUN_1410f2a10 = Double CFB decrypt
        Address addr = currentProgram.getAddressFactory().getAddress("1410f2a10");
        Function f = currentProgram.getFunctionManager().getFunctionAt(addr);
        println("=== FUN_1410f2a10 (Double CFB decrypt) ===");
        DecompileResults r = d.decompileFunction(f, 120, monitor);
        if (r.decompileCompleted()) {
            for (String line : r.getDecompiledFunction().getC().split("\n"))
                println(line);
        }
        d.dispose();
    }
}
