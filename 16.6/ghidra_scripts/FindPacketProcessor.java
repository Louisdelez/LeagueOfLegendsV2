//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class FindPacketProcessor extends GhidraScript {
    public void run() throws Exception {
        Address base = currentProgram.getImageBase();
        
        // FUN_14057d4c0 is called with packet data in FUN_140588730
        // It might be the packet processing/encryption function
        Function proc = getFunctionAt(base.add(0x57D4C0L));
        if (proc == null) { println("FUN_14057d4c0 not found"); return; }
        
        println("=== FUN_14057d4c0 (packet processor?) ===");
        ghidra.app.decompiler.DecompInterface d = new ghidra.app.decompiler.DecompInterface();
        d.openProgram(currentProgram);
        ghidra.app.decompiler.DecompileResults r = d.decompileFunction(proc, 120, monitor);
        if (r.decompileCompleted()) {
            String code = r.getDecompiledFunction().getC();
            String[] lines = code.split("\n");
            println("(" + lines.length + " lines)");
            
            // Check for crypto patterns
            boolean hasXor = code.contains(" ^ ");
            boolean hasShift = code.contains(" << ") || code.contains(" >> ");
            boolean hasMul = code.contains(" * ");
            println("Patterns: xor=" + hasXor + " shift=" + hasShift + " mul=" + hasMul);
            
            for (int i = 0; i < Math.min(lines.length, 200); i++) println(lines[i]);
            if (lines.length > 200) println("... (" + (lines.length - 200) + " more)");
        }
        d.dispose();
        
        // Find ALL functions called BY FUN_14057d4c0 (what does it call?)
        println("\n=== Functions called by FUN_14057d4c0 ===");
        for (Instruction inst : currentProgram.getListing().getInstructions(proc.getBody(), true)) {
            if (inst.getMnemonicString().equals("CALL")) {
                Reference[] callRefs = inst.getReferencesFrom();
                for (Reference ref : callRefs) {
                    Function target = getFunctionAt(ref.getToAddress());
                    if (target != null) {
                        println("  Calls " + target.getName() + " at " + target.getEntryPoint());
                    }
                }
            }
        }
        
        // Also check: what about the function that adds to the queue?
        // In the send loop NET_58e860, the queue is at param_1 + 0xB0 area
        // The enqueue function should be BEFORE FUN_140588730 in the pipeline
        // Let's look at callers of FUN_140588730
        println("\n=== Callers of FUN_140588730 ===");
        Function f588 = getFunctionAt(base.add(0x588730L));
        if (f588 != null) {
            Reference[] refs = getReferencesTo(f588.getEntryPoint());
            println("Callers: " + refs.length);
            java.util.Set<String> seen = new java.util.HashSet<>();
            for (Reference ref : refs) {
                Function c = getFunctionContaining(ref.getFromAddress());
                if (c != null && seen.add(c.getName())) {
                    println("  " + c.getName() + " at " + c.getEntryPoint());
                    // Decompile briefly
                    ghidra.app.decompiler.DecompInterface d2 = new ghidra.app.decompiler.DecompInterface();
                    d2.openProgram(currentProgram);
                    ghidra.app.decompiler.DecompileResults r2 = d2.decompileFunction(c, 60, monitor);
                    if (r2.decompileCompleted()) {
                        String code2 = r2.getDecompiledFunction().getC();
                        boolean hasXor2 = code2.contains(" ^ ");
                        boolean hasShift2 = code2.contains(" << ") || code2.contains(" >> ");
                        println("    Patterns: xor=" + hasXor2 + " shift=" + hasShift2 + " lines=" + code2.split("\n").length);
                    }
                    d2.dispose();
                }
            }
        }
        
        println("\n=== DONE ===");
    }
}
