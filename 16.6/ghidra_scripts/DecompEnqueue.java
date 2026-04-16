//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class DecompEnqueue extends GhidraScript {
    public void run() throws Exception {
        Address base = currentProgram.getImageBase();
        
        // Key functions to analyze:
        // FUN_140571D80 - Signal caller, potential enqueue
        // FUN_14056BD90 - Signal caller, potential enqueue
        // FUN_14056E310 - called in send loop before data copy
        // FUN_140588730 - Signal caller in same code area
        // FUN_1405883D0 - Signal caller in same code area
        
        long[] offsets = { 0x571D80L, 0x56BD90L, 0x56E310L, 0x588730L, 0x5883D0L };
        
        for (long off : offsets) {
            Address addr = base.add(off);
            Function f = getFunctionAt(addr);
            if (f == null) f = getFunctionContaining(addr);
            if (f == null) continue;
            
            println("\n==========================================");
            println(f.getName() + " at " + f.getEntryPoint() + " (offset 0x" + Long.toHexString(off) + ")");
            println("==========================================");
            
            ghidra.app.decompiler.DecompInterface d = new ghidra.app.decompiler.DecompInterface();
            d.openProgram(currentProgram);
            ghidra.app.decompiler.DecompileResults r = d.decompileFunction(f, 120, monitor);
            if (r.decompileCompleted()) {
                String code = r.getDecompiledFunction().getC();
                // Search for interesting patterns in the code
                boolean hasEncrypt = code.contains("encrypt") || code.contains("crypt") || code.contains("cipher");
                boolean hasXor = code.contains(" ^ ") || code.contains("XOR");
                boolean hasQueue = code.contains("0xb8") || code.contains("0xc0") || code.contains("0xd0");
                boolean hasSend = code.contains("send") || code.contains("519") || code.contains("0x207");
                boolean hasKey = code.contains("key") || code.contains("Key");
                
                println("Patterns: encrypt=" + hasEncrypt + " xor=" + hasXor + " queue=" + hasQueue + " send=" + hasSend + " key=" + hasKey);
                
                String[] lines = code.split("\n");
                // If it has interesting patterns, show full code
                if (hasXor || hasQueue || hasSend || hasEncrypt || hasKey) {
                    for (int i = 0; i < Math.min(lines.length, 200); i++) println(lines[i]);
                    if (lines.length > 200) println("... (" + (lines.length - 200) + " more)");
                } else {
                    // Just show first 30 lines
                    for (int i = 0; i < Math.min(lines.length, 30); i++) println(lines[i]);
                    println("... (" + lines.length + " total, no interesting patterns)");
                }
            }
            d.dispose();
            
            // Callers
            Reference[] refs = getReferencesTo(f.getEntryPoint());
            println("Callers (" + refs.length + "):");
            java.util.Set<String> seen = new java.util.HashSet<>();
            for (Reference ref : refs) {
                Function c = getFunctionContaining(ref.getFromAddress());
                if (c != null && seen.add(c.getName()))
                    println("  " + c.getName() + " at " + c.getEntryPoint());
            }
        }
        println("\n=== DONE ===");
    }
}
