//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class FindQueueSignal extends GhidraScript {
    public void run() throws Exception {
        Address base = currentProgram.getImageBase();
        
        // FUN_1418555d0 = CondVar_Signal (15 callers)
        // We need callers that pass param + 0xd8 (the network queue condvar)
        Function signal = getFunctionAt(base.add(0x18555D0L));
        if (signal == null) { println("Signal function not found"); return; }
        
        Reference[] refs = getReferencesTo(signal.getEntryPoint());
        println("Signal callers: " + refs.length);
        
        java.util.Set<String> seen = new java.util.HashSet<>();
        for (Reference ref : refs) {
            Function caller = getFunctionContaining(ref.getFromAddress());
            if (caller == null || !seen.add(caller.getName())) continue;
            
            // Decompile and check if it uses +0xd8
            ghidra.app.decompiler.DecompInterface d = new ghidra.app.decompiler.DecompInterface();
            d.openProgram(currentProgram);
            ghidra.app.decompiler.DecompileResults r = d.decompileFunction(caller, 120, monitor);
            if (r.decompileCompleted()) {
                String code = r.getDecompiledFunction().getC();
                if (code.contains("0xd8") || code.contains("+ 0xd8") || code.contains("+0xd8")) {
                    println("\n*** QUEUE SIGNAL CALLER: " + caller.getName() + " at " + caller.getEntryPoint() + " ***");
                    println("Uses offset 0xd8 (network queue condvar)!");
                    String[] lines = code.split("\n");
                    for (int i = 0; i < Math.min(lines.length, 200); i++) println(lines[i]);
                    if (lines.length > 200) println("... (" + (lines.length - 200) + " more)");
                    
                    // Find callers of THIS function too
                    Reference[] callerRefs = getReferencesTo(caller.getEntryPoint());
                    if (callerRefs.length > 0 && callerRefs.length < 20) {
                        println("\nCallers of " + caller.getName() + " (" + callerRefs.length + "):");
                        for (Reference cr : callerRefs) {
                            Function gc = getFunctionContaining(cr.getFromAddress());
                            if (gc != null) println("  " + gc.getName() + " at " + gc.getEntryPoint());
                        }
                    }
                } else {
                    println("  " + caller.getName() + " - no 0xd8 offset");
                }
            }
            d.dispose();
        }
        println("\n=== DONE ===");
    }
}
