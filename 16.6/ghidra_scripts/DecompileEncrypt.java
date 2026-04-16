//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class DecompileEncrypt extends GhidraScript {
    public void run() throws Exception {
        Address base = currentProgram.getImageBase();
        
        // FUN_140596260 - likely encryption function called before sendto
        long[] offsets = { 0x596260L, 0x58E580L };
        String[] names = { "EncryptCandidate", "SendtoContainer" };
        
        for (int idx = 0; idx < offsets.length; idx++) {
            Address addr = base.add(offsets[idx]);
            Function func = getFunctionAt(addr);
            if (func == null) func = getFunctionContaining(addr);
            
            println("\n==========================================");
            println(names[idx] + " at offset 0x" + Long.toHexString(offsets[idx]));
            if (func != null) {
                println("Function: " + func.getName() + " at " + func.getEntryPoint());
                ghidra.app.decompiler.DecompInterface d = new ghidra.app.decompiler.DecompInterface();
                d.openProgram(currentProgram);
                ghidra.app.decompiler.DecompileResults r = d.decompileFunction(func, 120, monitor);
                if (r.decompileCompleted()) {
                    String[] lines = r.getDecompiledFunction().getC().split("\n");
                    for (int i = 0; i < Math.min(lines.length, 300); i++) println(lines[i]);
                    if (lines.length > 300) println("... (" + (lines.length - 300) + " more)");
                }
                d.dispose();
                
                Reference[] refs = getReferencesTo(func.getEntryPoint());
                println("\nCallers (" + refs.length + "):");
                java.util.Set<String> seen = new java.util.HashSet<>();
                for (Reference ref : refs) {
                    Function c = getFunctionContaining(ref.getFromAddress());
                    if (c != null && seen.add(c.getName()))
                        println("  " + c.getName() + " at " + c.getEntryPoint());
                }
            } else {
                println("No function found");
            }
        }
        println("\n=== DONE ===");
    }
}
