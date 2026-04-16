import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;
public class DecompRecvCryptoFull extends GhidraScript {
    public void run() throws Exception {
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        // RECV crypto function (like FUN_1410f41e0 but for receive)
        String[] addrs = {"1410f2a10", "1410f25c0"};
        for (String a : addrs) {
            Address addr = currentProgram.getAddressFactory().getAddress(a);
            Function f = currentProgram.getFunctionManager().getFunctionAt(addr);
            if (f == null) { println("NO FUNC at " + a); continue; }
            println("=== " + f.getName() + " at " + a + " size=" + f.getBody().getNumAddresses() + " ===");
            DecompileResults r = d.decompileFunction(f, 120, monitor);
            if (r.decompileCompleted()) {
                for (String line : r.getDecompiledFunction().getC().split("\n")) println(line);
            }
        }
        d.dispose();
    }
}
