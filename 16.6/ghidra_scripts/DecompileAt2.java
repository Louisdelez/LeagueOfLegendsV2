//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class DecompileAt2 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address base = currentProgram.getImageBase();
        Address callAddr = base.add(0x58ECBBL);
        println("Looking at " + callAddr);

        byte[] bytes = new byte[32];
        currentProgram.getMemory().getBytes(callAddr.add(-16), bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02X ", b & 0xFF));
        println("Bytes: " + sb.toString());

        for (long off = 0; off < 0x2000; off++) {
            Address tryAddr = callAddr.add(-off);
            Function f = getFunctionAt(tryAddr);
            if (f != null) {
                println("Function: " + f.getName() + " at " + f.getEntryPoint());
                ghidra.app.decompiler.DecompInterface d = new ghidra.app.decompiler.DecompInterface();
                d.openProgram(currentProgram);
                ghidra.app.decompiler.DecompileResults r = d.decompileFunction(f, 120, monitor);
                if (r.decompileCompleted()) {
                    String[] lines = r.getDecompiledFunction().getC().split("\n");
                    for (int i = 0; i < Math.min(lines.length, 500); i++) println(lines[i]);
                }
                d.dispose();

                Reference[] refs = getReferencesTo(f.getEntryPoint());
                println("Callers (" + refs.length + "):");
                java.util.Set<String> seen = new java.util.HashSet<>();
                for (Reference ref : refs) {
                    Function c = getFunctionContaining(ref.getFromAddress());
                    if (c != null && seen.add(c.getName()))
                        println("  " + c.getName() + " at " + c.getEntryPoint());
                }
                break;
            }
        }
        println("=== DONE ===");
    }
}
