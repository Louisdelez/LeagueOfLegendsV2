//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class FindEnqueue extends GhidraScript {
    public void run() throws Exception {
        Address base = currentProgram.getImageBase();

        // NET_58e860 is the send loop. Find its callers.
        Function sendLoop = getFunctionAt(base.add(0x58E860L));
        if (sendLoop == null) {
            println("NET_58e860 not found!");
            return;
        }

        println("=== Callers of " + sendLoop.getName() + " ===");
        Reference[] refs = getReferencesTo(sendLoop.getEntryPoint());
        println("Total: " + refs.length);

        java.util.Set<String> seen = new java.util.HashSet<>();
        for (Reference ref : refs) {
            Function caller = getFunctionContaining(ref.getFromAddress());
            if (caller != null && seen.add(caller.getName())) {
                println("\n--- CALLER: " + caller.getName() + " at " + caller.getEntryPoint() + " ---");

                ghidra.app.decompiler.DecompInterface d = new ghidra.app.decompiler.DecompInterface();
                d.openProgram(currentProgram);
                ghidra.app.decompiler.DecompileResults r = d.decompileFunction(caller, 120, monitor);
                if (r.decompileCompleted()) {
                    String[] lines = r.getDecompiledFunction().getC().split("\n");
                    for (int i = 0; i < Math.min(lines.length, 150); i++) println(lines[i]);
                    if (lines.length > 150) println("... (" + (lines.length - 150) + " more)");
                }
                d.dispose();

                // Also find callers of caller
                Reference[] callerRefs = getReferencesTo(caller.getEntryPoint());
                if (callerRefs.length > 0 && callerRefs.length < 20) {
                    println("  Callers of " + caller.getName() + " (" + callerRefs.length + "):");
                    for (Reference cr : callerRefs) {
                        Function gc = getFunctionContaining(cr.getFromAddress());
                        if (gc != null) println("    " + gc.getName() + " at " + gc.getEntryPoint());
                    }
                }
            }
        }

        // Also find the enqueue function
        // The send loop reads from a circular buffer at param_1+0xB8
        // The enqueue writes to the same buffer
        // FUN_14056e310 is called in the send loop - maybe it's the enqueue or related
        println("\n=== FUN_14056e310 (called in send loop) ===");
        Function f = getFunctionAt(base.add(0x56E310L));
        if (f != null) {
            ghidra.app.decompiler.DecompInterface d = new ghidra.app.decompiler.DecompInterface();
            d.openProgram(currentProgram);
            ghidra.app.decompiler.DecompileResults r = d.decompileFunction(f, 120, monitor);
            if (r.decompileCompleted()) {
                String[] lines = r.getDecompiledFunction().getC().split("\n");
                for (int i = 0; i < Math.min(lines.length, 100); i++) println(lines[i]);
            }
            d.dispose();
        }

        println("\n=== DONE ===");
    }
}
