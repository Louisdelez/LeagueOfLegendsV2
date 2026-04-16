import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;

public class DecompRealHandler extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        Address addr = currentProgram.getAddressFactory().getAddress("140573160");
        Function func = currentProgram.getFunctionManager().getFunctionContaining(addr);
        if (func == null) func = currentProgram.getFunctionManager().getFunctionAt(addr);
        
        if (func != null) {
            println("=== REAL HANDLER at " + func.getEntryPoint() + " " + func.getName() +
                    " size=" + func.getBody().getNumAddresses() + " ===");
            DecompileResults result = decomp.decompileFunction(func, 300, monitor);
            if (result.decompileCompleted()) {
                for (String line : result.getDecompiledFunction().getC().split("\n"))
                    println(line);
            }
        } else {
            println("No function at 140573160!");
        }
        println("\n=== DONE ===");
        decomp.dispose();
    }
}
