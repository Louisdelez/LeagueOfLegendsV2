import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;

public class DecompMainLoop extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // FUN_14057af90 is the main network loop caller
        Address addr = currentProgram.getAddressFactory().getAddress("14057af90");
        Function func = currentProgram.getFunctionManager().getFunctionAt(addr);

        if (func != null) {
            println("=== MAIN NETWORK LOOP: " + func.getName() + " ===");
            println("Size: " + func.getBody().getNumAddresses());

            DecompileResults result = decomp.decompileFunction(func, 120, monitor);
            if (result.decompileCompleted()) {
                String code = result.getDecompiledFunction().getC();
                String[] lines = code.split("\n");
                println("Lines: " + lines.length);
                for (String line : lines) {
                    println(line);
                }
            }

            // Find its callers too
            println("\n=== CALLERS ===");
            var refs = currentProgram.getReferenceManager().getReferencesTo(func.getEntryPoint());
            while (refs.hasNext()) {
                var ref = refs.next();
                Function caller = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                if (caller != null) {
                    println("  " + caller.getName() + " at " + caller.getEntryPoint());
                }
            }
        }

        println("\n=== DONE ===");
        decomp.dispose();
    }
}
