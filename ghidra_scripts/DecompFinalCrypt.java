//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class DecompFinalCrypt extends GhidraScript {
    public void run() throws Exception {
        Address base = currentProgram.getImageBase();
        
        // FUN_1410f41e0 - the actual encryption function
        // Called with (key_ctx, data, length, mode=2)
        Function f = getFunctionAt(base.add(0x10F41E0L));
        if (f == null) f = getFunctionContaining(base.add(0x10F41E0L));
        if (f == null) { println("NOT FOUND"); return; }
        
        println("=== CRYPTO CORE: " + f.getName() + " at " + f.getEntryPoint() + " ===");
        ghidra.app.decompiler.DecompInterface d = new ghidra.app.decompiler.DecompInterface();
        d.openProgram(currentProgram);
        ghidra.app.decompiler.DecompileResults r = d.decompileFunction(f, 120, monitor);
        if (r.decompileCompleted()) {
            String[] lines = r.getDecompiledFunction().getC().split("\n");
            println("Lines: " + lines.length);
            for (String line : lines) println(line);
        }
        d.dispose();
        
        // Functions it calls
        println("\n=== Calls ===");
        for (Instruction inst : currentProgram.getListing().getInstructions(f.getBody(), true)) {
            if (inst.getMnemonicString().equals("CALL")) {
                Reference[] refs = inst.getReferencesFrom();
                for (Reference ref : refs) {
                    Function target = getFunctionAt(ref.getToAddress());
                    if (target != null) println("  " + target.getName() + " at " + target.getEntryPoint());
                }
            }
        }
        
        // Also decompile FUN_14058bfb0 (the buffer write helper)
        println("\n=== BUFFER WRITE: FUN_14058bfb0 ===");
        Function bw = getFunctionAt(base.add(0x58BFB0L));
        if (bw != null) {
            ghidra.app.decompiler.DecompInterface d2 = new ghidra.app.decompiler.DecompInterface();
            d2.openProgram(currentProgram);
            ghidra.app.decompiler.DecompileResults r2 = d2.decompileFunction(bw, 60, monitor);
            if (r2.decompileCompleted()) {
                String[] lines2 = r2.getDecompiledFunction().getC().split("\n");
                for (String line : lines2) println(line);
            }
            d2.dispose();
        }
        
        println("\n=== DONE ===");
    }
}
