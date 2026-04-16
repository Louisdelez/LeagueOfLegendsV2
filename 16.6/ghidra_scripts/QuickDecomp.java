import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;
public class QuickDecomp extends GhidraScript {
    public void run() throws Exception {
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        String[] addrs = {"14057d260","140578660","14057d8e0","1405900b0"};
        for (String a : addrs) {
            Address addr = currentProgram.getAddressFactory().getAddress(a);
            Function f = currentProgram.getFunctionManager().getFunctionAt(addr);
            if (f == null) { println("NO FUNC at " + a); continue; }
            println("=== " + f.getName() + " at " + a + " size=" + f.getBody().getNumAddresses() + " ===");
            DecompileResults r = d.decompileFunction(f, 120, monitor);
            if (r.decompileCompleted()) {
                String[] lines = r.getDecompiledFunction().getC().split("\n");
                println("Lines: " + lines.length);
                for (String line : lines) println(line);
            }
        }
        d.dispose();
    }
}
