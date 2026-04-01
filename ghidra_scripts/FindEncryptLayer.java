import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class FindEncryptLayer extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address imageBase = currentProgram.getImageBase();

        // Callers of FUN_1801da010 (the send function)
        long[] callerOffsets = {
            0x1ce8c0L,  // FUN_1801ce8c0
            0x1d3000L,  // FUN_1801d3000
            0x1d73d0L,  // FUN_1801d73d0
            0x1da520L,  // FUN_1801da520
        };

        for (long offset : callerOffsets) {
            Address addr = imageBase.add(offset);
            Function func = getFunctionAt(addr);
            if (func == null) func = getFunctionContaining(addr);
            if (func == null) continue;

            println("\n==========================================");
            println(func.getName() + " at " + func.getEntryPoint());
            println("==========================================");
            decompile(func, 150);

            // Find callers (2 levels up)
            Reference[] refs = getReferencesTo(func.getEntryPoint());
            if (refs.length > 0 && refs.length < 30) {
                println("Callers (" + refs.length + "):");
                Set<String> seen = new HashSet<>();
                for (Reference ref : refs) {
                    Function c = getFunctionContaining(ref.getFromAddress());
                    if (c != null && !seen.contains(c.getName())) {
                        seen.add(c.getName());
                        println("  " + c.getName() + " at " + c.getEntryPoint());
                    }
                }
            }
        }

        println("\n=== DONE ===");
    }

    private void decompile(Function func, int maxLines) {
        try {
            ghidra.app.decompiler.DecompInterface d = new ghidra.app.decompiler.DecompInterface();
            d.openProgram(currentProgram);
            ghidra.app.decompiler.DecompileResults r = d.decompileFunction(func, 60, monitor);
            if (r.decompileCompleted()) {
                String[] lines = r.getDecompiledFunction().getC().split("\n");
                for (int i = 0; i < Math.min(lines.length, maxLines); i++) println(lines[i]);
                if (lines.length > maxLines) println("... (" + (lines.length - maxLines) + " more)");
            }
            d.dispose();
        } catch (Exception e) { println("Decompile error: " + e.getMessage()); }
    }
}
