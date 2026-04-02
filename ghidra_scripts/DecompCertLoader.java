import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
public class DecompCertLoader extends GhidraScript {
    public void run() throws Exception {
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        // FUN_140467430 - cert loader that refs Riot CA
        Address a = currentProgram.getAddressFactory().getAddress("140467430");
        Function f = currentProgram.getFunctionManager().getFunctionAt(a);
        if (f != null) {
            println("=== " + f.getName() + " size=" + f.getBody().getNumAddresses() + " ===");
            DecompileResults r = d.decompileFunction(f, 300, monitor);
            if (r.decompileCompleted()) {
                for (String l : r.getDecompiledFunction().getC().split("\n")) println(l);
            }
        }
        // Also FUN_1410fae90 - small crypto func that refs cert
        println("\n=== FUN_1410fae90 ===");
        a = currentProgram.getAddressFactory().getAddress("1410fae90");
        f = currentProgram.getFunctionManager().getFunctionAt(a);
        if (f != null) {
            println("size=" + f.getBody().getNumAddresses());
            DecompileResults r = d.decompileFunction(f, 180, monitor);
            if (r.decompileCompleted()) {
                for (String l : r.getDecompiledFunction().getC().split("\n")) println(l);
            }
        }
        println("\n=== DONE ===");
        d.dispose();
    }
}
