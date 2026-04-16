import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
public class DecompConsumerCmd2 extends GhidraScript {
    public void run() throws Exception {
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        Address addr = currentProgram.getAddressFactory().getAddress("1405883d0");
        Function fn = currentProgram.getFunctionManager().getFunctionAt(addr);
        if (fn != null) {
            println("=== FUN_1405883d0 size=" + fn.getBody().getNumAddresses() + " ===");
            DecompileResults r = d.decompileFunction(fn, 120, monitor);
            if (r.decompileCompleted()) {
                String code = r.getDecompiledFunction().getC();
                // Print FULL decompilation (not filtered)
                for (String line : code.split("\n"))
                    println(line);
            }
        }
        d.dispose();
    }
}
