import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
public class FindSSLCtx extends GhidraScript {
    public void run() throws Exception {
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        Address a = currentProgram.getAddressFactory().getAddress("14072c1f0");
        println("=== Xrefs to FUN_14072c1f0 (SSL config init) ===");
        for (var ref : currentProgram.getReferenceManager().getReferencesTo(a)) {
            Address from = ref.getFromAddress();
            Function fn = currentProgram.getFunctionManager().getFunctionContaining(from);
            if (fn != null) {
                println("  From " + from + " in " + fn.getName() + " at " + fn.getEntryPoint() + " size=" + fn.getBody().getNumAddresses());
                // Decompile to find what param_1 is
                DecompileResults r = d.decompileFunction(fn, 180, monitor);
                if (r.decompileCompleted()) {
                    String[] lines = r.getDecompiledFunction().getC().split("\n");
                    // Find lines with 72c1f0 call
                    for (int i = 0; i < lines.length; i++) {
                        if (lines[i].contains("FUN_14072c1f0") || lines[i].contains("72c1f0")) {
                            // Print surrounding context
                            for (int j = Math.max(0, i-3); j <= Math.min(lines.length-1, i+3); j++)
                                println("    [" + j + "] " + lines[j]);
                            break;
                        }
                    }
                }
            }
        }
        println("=== DONE ===");
        d.dispose();
    }
}
