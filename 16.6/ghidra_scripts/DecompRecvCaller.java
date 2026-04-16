import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;

public class DecompRecvCaller extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // recvfrom is called from +0x58B099
        // Find the function containing this address
        Address callAddr = currentProgram.getAddressFactory().getAddress("14058b099");
        Function func = currentProgram.getFunctionManager().getFunctionContaining(callAddr);

        if (func == null) {
            println("No function at 14058b099! Trying nearby...");
            // Try a few nearby addresses
            for (long off = -0x1000; off <= 0x1000; off += 0x1) {
                Address tryAddr = currentProgram.getAddressFactory().getAddress(
                    String.format("%x", 0x14058b099L + off));
                func = currentProgram.getFunctionManager().getFunctionContaining(tryAddr);
                if (func != null) {
                    println("Found function at offset " + off + ": " + func.getEntryPoint());
                    break;
                }
            }
        }

        if (func != null) {
            println("=== RECV CALLER: " + func.getName() + " at " + func.getEntryPoint() +
                    " (size=" + func.getBody().getNumAddresses() + ") ===");
            println("recvfrom call at: 14058b099");

            DecompileResults result = decomp.decompileFunction(func, 120, monitor);
            if (result.decompileCompleted()) {
                String code = result.getDecompiledFunction().getC();
                String[] lines = code.split("\n");
                println("Lines: " + lines.length);
                for (String line : lines) {
                    println(line);
                }
            }

            // Also decompile the function that CALLS this one
            println("\n=== LOOKING FOR CALLERS OF " + func.getName() + " ===");
            var refs = currentProgram.getReferenceManager().getReferencesTo(func.getEntryPoint());
            int count = 0;
            while (refs.hasNext() && count < 5) {
                var ref = refs.next();
                Function caller = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                if (caller != null) {
                    count++;
                    println("  Caller: " + caller.getName() + " at " + caller.getEntryPoint());
                }
            }
        }

        println("\n=== DONE ===");
        decomp.dispose();
    }
}
