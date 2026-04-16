//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class DecompCrypt extends GhidraScript {
    public void run() throws Exception {
        Address base = currentProgram.getImageBase();
        Function f = getFunctionAt(base.add(0x58EF90L));
        if (f == null) { println("Not found! Searching..."); f = getFunctionContaining(base.add(0x58EF90L)); }
        if (f == null) { println("Still not found"); return; }
        
        println("=== ENCRYPTION FUNCTION: " + f.getName() + " at " + f.getEntryPoint() + " ===");
        ghidra.app.decompiler.DecompInterface d = new ghidra.app.decompiler.DecompInterface();
        d.openProgram(currentProgram);
        ghidra.app.decompiler.DecompileResults r = d.decompileFunction(f, 120, monitor);
        if (r.decompileCompleted()) {
            String[] lines = r.getDecompiledFunction().getC().split("\n");
            println("Lines: " + lines.length);
            for (String line : lines) println(line);
        }
        d.dispose();
        
        // Also list ALL functions it calls
        println("\n=== Functions called ===");
        for (Instruction inst : currentProgram.getListing().getInstructions(f.getBody(), true)) {
            if (inst.getMnemonicString().equals("CALL")) {
                Reference[] refs = inst.getReferencesFrom();
                for (Reference ref : refs) {
                    Function target = getFunctionAt(ref.getToAddress());
                    if (target != null) println("  " + target.getName() + " at " + target.getEntryPoint());
                }
            }
        }
        
        println("\n=== DONE ===");
    }
}
