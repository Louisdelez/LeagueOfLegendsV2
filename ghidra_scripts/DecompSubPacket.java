import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
public class DecompSubPacket extends GhidraScript {
    public void run() throws Exception {
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        // FUN_14055b9a0 - sub-packet reader
        Address addr = currentProgram.getAddressFactory().getAddress("14055b9a0");
        Function fn = currentProgram.getFunctionManager().getFunctionAt(addr);
        if (fn != null) {
            println("=== FUN_14055b9a0 (sub-packet reader) size=" + fn.getBody().getNumAddresses() + " ===");
            DecompileResults r = d.decompileFunction(fn, 60, monitor);
            if (r.decompileCompleted())
                for (String line : r.getDecompiledFunction().getC().split("\n"))
                    println(line);
        }
        d.dispose();
    }
}
