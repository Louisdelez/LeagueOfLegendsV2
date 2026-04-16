//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class DecompSignalCallers extends GhidraScript {
    public void run() throws Exception {
        Address base = currentProgram.getImageBase();
        // Callers of CondVar_Signal in the 0x58xxxx range (network code area)
        long[] callers = {
            0x593B30L, 0x571D80L, 0x56BD90L, 0x5883D0L,
            0x589A90L, 0x5897F0L, 0x589970L, 0x588730L
        };
        for (long off : callers) {
            Function f = getFunctionAt(base.add(off));
            if (f == null) f = getFunctionContaining(base.add(off));
            if (f == null) continue;
            println("\n=== " + f.getName() + " at " + f.getEntryPoint() + " ===");
            ghidra.app.decompiler.DecompInterface d = new ghidra.app.decompiler.DecompInterface();
            d.openProgram(currentProgram);
            ghidra.app.decompiler.DecompileResults r = d.decompileFunction(f, 120, monitor);
            if (r.decompileCompleted()) {
                String[] lines = r.getDecompiledFunction().getC().split("\n");
                for (int i = 0; i < Math.min(lines.length, 100); i++) println(lines[i]);
                if (lines.length > 100) println("... (" + (lines.length - 100) + " more)");
            }
            d.dispose();
        }
        println("\n=== DONE ===");
    }
}
