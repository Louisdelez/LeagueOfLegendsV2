import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
public class FindTrustVector extends GhidraScript {
    public void run() throws Exception {
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        Address a = currentProgram.getAddressFactory().getAddress("1410fbdc0");
        println("=== Xrefs to FUN_1410fbdc0 (cert vector builder) ===");
        for (var ref : currentProgram.getReferenceManager().getReferencesTo(a)) {
            Address from = ref.getFromAddress();
            Function fn = currentProgram.getFunctionManager().getFunctionContaining(from);
            if (fn != null) {
                println("  From " + from + " in " + fn.getName() + " at " + fn.getEntryPoint() + " size=" + fn.getBody().getNumAddresses());
                DecompileResults r = d.decompileFunction(fn, 180, monitor);
                if (r.decompileCompleted()) {
                    String[] lines = r.getDecompiledFunction().getC().split("\n");
                    println("  Lines: " + lines.length);
                    for (int i = 0; i < Math.min(40, lines.length); i++) println("    " + lines[i]);
                }
            }
        }
        println("\n=== DONE ===");
        d.dispose();
    }
}
