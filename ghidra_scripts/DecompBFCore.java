import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;

public class DecompBFCore extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // FUN_1410f3d90 = the BF_encrypt core used by FUN_1410f41e0
        Address addr = currentProgram.getAddressFactory().getAddress("1410f3d90");
        Function func = currentProgram.getFunctionManager().getFunctionAt(addr);

        if (func == null) {
            println("Function not found at 1410f3d90!");
            return;
        }

        println("=== BF_ENCRYPT CORE: " + func.getName() + " at " + addr + " ===");

        DecompileResults result = decomp.decompileFunction(func, 120, monitor);
        if (result.decompileCompleted()) {
            String code = result.getDecompiledFunction().getC();
            String[] lines = code.split("\n");
            println("Lines: " + lines.length);
            for (String line : lines) {
                println(line);
            }
        } else {
            println("Decompilation failed: " + result.getErrorMessage());
        }

        println("\n=== DONE ===");
        decomp.dispose();
    }
}
