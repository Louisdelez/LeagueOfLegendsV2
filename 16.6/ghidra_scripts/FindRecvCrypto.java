import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class FindRecvCrypto extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // FUN_1410f2ce0 is the OTHER crypto function (uses FUN_1410f25c0 as BF core)
        // This might be the RECEIVE path decryptor

        Address cryptoAddr = currentProgram.getAddressFactory().getAddress("1410f2ce0");
        Function cryptoFunc = currentProgram.getFunctionManager().getFunctionAt(cryptoAddr);

        if (cryptoFunc == null) {
            println("Function not found at 1410f2ce0!");
            return;
        }

        println("=== ALL CALLERS OF FUN_1410f2ce0 (OTHER crypto function) ===");
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(cryptoAddr);
        int count = 0;
        while (refs.hasNext()) {
            Reference ref = refs.next();
            Address caller = ref.getFromAddress();
            Function callerFunc = currentProgram.getFunctionManager().getFunctionContaining(caller);
            if (callerFunc != null) {
                count++;
                println("  [" + count + "] " + callerFunc.getName() + " at " + callerFunc.getEntryPoint() +
                        " (call from " + caller + ") size=" + callerFunc.getBody().getNumAddresses());

                // Decompile ALL callers
                DecompileResults result = decomp.decompileFunction(callerFunc, 120, monitor);
                if (result.decompileCompleted()) {
                    String code = result.getDecompiledFunction().getC();
                    String[] lines = code.split("\n");
                    println("    Decompiled (" + lines.length + " lines):");
                    for (String line : lines) {
                        println("    " + line);
                    }
                }
            }
        }

        // Also check FUN_1410f25c0 (the BF core used by FUN_1410f2ce0)
        println("\n=== CALLERS OF FUN_1410f25c0 (BF core for recv?) ===");
        Address bfCoreAddr = currentProgram.getAddressFactory().getAddress("1410f25c0");
        refs = currentProgram.getReferenceManager().getReferencesTo(bfCoreAddr);
        while (refs.hasNext()) {
            Reference ref = refs.next();
            Address caller = ref.getFromAddress();
            Function callerFunc = currentProgram.getFunctionManager().getFunctionContaining(caller);
            if (callerFunc != null) {
                println("  " + callerFunc.getName() + " at " + callerFunc.getEntryPoint() + " (from " + caller + ")");
            }
        }

        println("\n=== Total callers of FUN_1410f2ce0: " + count + " ===");
        println("=== DONE ===");
        decomp.dispose();
    }
}
