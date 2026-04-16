import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
public class DecompCertStore extends GhidraScript {
    public void run() throws Exception {
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);

        // FUN_1410fbb10 - small crypto func that refs Riot CA
        println("=== FUN_1410fbb10 ===");
        Function f = currentProgram.getFunctionManager().getFunctionAt(
            currentProgram.getAddressFactory().getAddress("1410fbb10"));
        if (f != null) {
            println("size=" + f.getBody().getNumAddresses());
            DecompileResults r = d.decompileFunction(f, 180, monitor);
            if (r.decompileCompleted()) for (String l : r.getDecompiledFunction().getC().split("\n")) println(l);
        }

        // FUN_1410fbdc0 - big crypto func (1777 bytes) that refs cert 
        println("\n=== FUN_1410fbdc0 ===");
        f = currentProgram.getFunctionManager().getFunctionAt(
            currentProgram.getAddressFactory().getAddress("1410fbdc0"));
        if (f != null) {
            println("size=" + f.getBody().getNumAddresses());
            DecompileResults r = d.decompileFunction(f, 300, monitor);
            if (r.decompileCompleted()) {
                String[] lines = r.getDecompiledFunction().getC().split("\n");
                println("Lines: " + lines.length);
                // Print lines that reference cert data or store operations
                for (int i = 0; i < lines.length; i++) {
                    String l = lines[i];
                    if (l.contains("19EE") || l.contains("DAT_") || l.contains("store") || 
                        l.contains("trust") || l.contains("x509") || l.contains("verify") ||
                        l.contains("param_") || l.contains("FUN_") || l.contains("return") ||
                        i < 5 || i > lines.length - 3) {
                        println("[" + i + "] " + l);
                    }
                }
            }
        }

        // FUN_140ac45d0 - small function (45 bytes) that refs cert
        println("\n=== FUN_140ac45d0 ===");
        f = currentProgram.getFunctionManager().getFunctionAt(
            currentProgram.getAddressFactory().getAddress("140ac45d0"));
        if (f != null) {
            println("size=" + f.getBody().getNumAddresses());
            DecompileResults r = d.decompileFunction(f, 180, monitor);
            if (r.decompileCompleted()) for (String l : r.getDecompiledFunction().getC().split("\n")) println(l);
        }

        println("\n=== DONE ===");
        d.dispose();
    }
}
