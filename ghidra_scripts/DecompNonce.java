import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;
public class DecompNonce extends GhidraScript {
    public void run() throws Exception {
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        Address addr = currentProgram.getAddressFactory().getAddress("140577f10");
        Function f = currentProgram.getFunctionManager().getFunctionAt(addr);
        if (f == null) { println("NO FUNC"); return; }
        println("=== FUN_140577f10 (NONCE GENERATOR) size=" + f.getBody().getNumAddresses() + " ===");
        DecompileResults r = d.decompileFunction(f, 120, monitor);
        if (r.decompileCompleted()) {
            for (String line : r.getDecompiledFunction().getC().split("\n")) println(line);
        }
        d.dispose();
    }
}
