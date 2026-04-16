import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class FindCryptoCallers extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // FUN_1410f41e0 is the CFB crypto function
        // FUN_14058ef90 is the SEND path encryptor (calls FUN_1410f41e0 twice)
        // There MUST be a RECEIVE path that also calls FUN_1410f41e0

        Address cryptoAddr = currentProgram.getAddressFactory().getAddress("1410f41e0");
        Function cryptoFunc = currentProgram.getFunctionManager().getFunctionAt(cryptoAddr);

        if (cryptoFunc == null) {
            println("Crypto function not found at 1410f41e0!");
            return;
        }

        println("=== ALL CALLERS OF FUN_1410f41e0 (crypto CFB) ===");
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(cryptoAddr);
        int count = 0;
        while (refs.hasNext()) {
            Reference ref = refs.next();
            Address caller = ref.getFromAddress();
            Function callerFunc = currentProgram.getFunctionManager().getFunctionContaining(caller);
            if (callerFunc != null) {
                count++;
                boolean isSendPath = callerFunc.getEntryPoint().toString().contains("58ef90");
                println("  [" + count + "] " + callerFunc.getName() + " at " + callerFunc.getEntryPoint() +
                        " (call from " + caller + ")" +
                        (isSendPath ? " ← KNOWN SEND PATH" : " ← POSSIBLE RECV PATH!"));

                // Decompile non-send callers to find the receive path
                if (!isSendPath) {
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
        }

        println("\n=== Total callers: " + count + " ===");
        println("=== DONE ===");
        decomp.dispose();
    }
}
