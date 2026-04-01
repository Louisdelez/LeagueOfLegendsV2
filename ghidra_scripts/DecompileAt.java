import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class DecompileAt extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address base = currentProgram.getImageBase();
        
        // The sendto caller is at offset 0x58ECBB
        Address callAddr = base.add(0x58ECBB);
        println("Call address: " + callAddr);
        
        Function func = getFunctionContaining(callAddr);
        if (func == null) {
            println("No function found at this address!");
            // Try nearby
            for (long delta = -0x100; delta <= 0x100; delta += 0x10) {
                func = getFunctionContaining(callAddr.add(delta));
                if (func != null) {
                    println("Found function at " + func.getEntryPoint() + " (delta=" + delta + ")");
                    break;
                }
            }
        }
        
        if (func != null) {
            println("\n=== SEND FUNCTION: " + func.getName() + " at " + func.getEntryPoint() + " ===");
            println("Call to sendto at offset +0x" + Long.toHexString(callAddr.subtract(func.getEntryPoint())));
            
            // Decompile
            ghidra.app.decompiler.DecompInterface d = new ghidra.app.decompiler.DecompInterface();
            d.openProgram(currentProgram);
            ghidra.app.decompiler.DecompileResults r = d.decompileFunction(func, 120, monitor);
            if (r.decompileCompleted()) {
                String code = r.getDecompiledFunction().getC();
                println(code);
            }
            d.dispose();
            
            // Find callers of THIS function
            println("\n=== CALLERS ===");
            Reference[] refs = getReferencesTo(func.getEntryPoint());
            println("References: " + refs.length);
            java.util.Set<String> seen = new java.util.HashSet<>();
            for (Reference ref : refs) {
                Function caller = getFunctionContaining(ref.getFromAddress());
                if (caller != null && !seen.contains(caller.getName())) {
                    seen.add(caller.getName());
                    println("  " + caller.getName() + " at " + caller.getEntryPoint());
                    
                    // Decompile callers too
                    ghidra.app.decompiler.DecompInterface d2 = new ghidra.app.decompiler.DecompInterface();
                    d2.openProgram(currentProgram);
                    ghidra.app.decompiler.DecompileResults r2 = d2.decompileFunction(caller, 120, monitor);
                    if (r2.decompileCompleted()) {
                        String[] lines = r2.getDecompiledFunction().getC().split("\n");
                        println("  --- " + caller.getName() + " (" + lines.length + " lines) ---");
                        for (int i = 0; i < Math.min(lines.length, 80); i++) println("  " + lines[i]);
                        if (lines.length > 80) println("  ... (" + (lines.length - 80) + " more)");
                    }
                    d2.dispose();
                }
            }
        }
        
        println("\n=== DONE ===");
    }
}
