//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class DecompPacketInit extends GhidraScript {
    public void run() throws Exception {
        Address base = currentProgram.getImageBase();
        
        // FUN_140567550 - called to init packet buffer (0x350 bytes)
        // This might do the encryption!
        long[] offsets = { 0x567550L, 0x2287F0L };
        String[] names = { "PacketInit(0x350)", "QueueInsert" };
        
        for (int idx = 0; idx < offsets.length; idx++) {
            Function f = getFunctionAt(base.add(offsets[idx]));
            if (f == null) continue;
            
            println("\n=== " + names[idx] + " = " + f.getName() + " ===");
            ghidra.app.decompiler.DecompInterface d = new ghidra.app.decompiler.DecompInterface();
            d.openProgram(currentProgram);
            ghidra.app.decompiler.DecompileResults r = d.decompileFunction(f, 120, monitor);
            if (r.decompileCompleted()) {
                String code = r.getDecompiledFunction().getC();
                boolean hasXor = code.contains(" ^ ");
                boolean hasShift = code.contains(" << ") || code.contains(" >> ");
                boolean hasLoop = code.contains("while") || code.contains("for (");
                println("Patterns: xor=" + hasXor + " shift=" + hasShift + " loop=" + hasLoop + " lines=" + code.split("\n").length);
                
                String[] lines = code.split("\n");
                for (int i = 0; i < Math.min(lines.length, 150); i++) println(lines[i]);
                if (lines.length > 150) println("... (" + (lines.length - 150) + " more)");
            }
            d.dispose();
            
            // Functions called by this function
            println("\nCalls:");
            for (Instruction inst : currentProgram.getListing().getInstructions(f.getBody(), true)) {
                if (inst.getMnemonicString().equals("CALL")) {
                    Reference[] refs = inst.getReferencesFrom();
                    for (Reference ref : refs) {
                        Function target = getFunctionAt(ref.getToAddress());
                        if (target != null)
                            println("  " + target.getName() + " at " + target.getEntryPoint());
                    }
                }
            }
        }
        println("\n=== DONE ===");
    }
}
