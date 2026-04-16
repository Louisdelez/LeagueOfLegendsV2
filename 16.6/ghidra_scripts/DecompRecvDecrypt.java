import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;
public class DecompRecvDecrypt extends GhidraScript {
    public void run() throws Exception {
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        // Functions called right after recvfrom in the recv loop
        String[] addrs = {"1410f48f0", "1410f6d20"};
        for (String a : addrs) {
            Address addr = currentProgram.getAddressFactory().getAddress(a);
            Function f = currentProgram.getFunctionManager().getFunctionAt(addr);
            if (f == null) { println("NO FUNC at " + a); continue; }
            println("=== " + f.getName() + " at " + a + " size=" + f.getBody().getNumAddresses() + " ===");
            DecompileResults r = d.decompileFunction(f, 120, monitor);
            if (r.decompileCompleted()) {
                for (String line : r.getDecompiledFunction().getC().split("\n")) println(line);
            }
            // Show what it calls
            println("--- Calls from " + f.getName() + " ---");
            var refs = f.getBody().getAddresses(true);
            // Use reference manager instead
            var callRefs = currentProgram.getReferenceManager().getReferenceIterator(f.getEntryPoint());
            java.util.Set<String> seen = new java.util.HashSet<>();
            while (callRefs.hasNext()) {
                var ref = callRefs.next();
                if (ref.getFromAddress().getOffset() > f.getEntryPoint().getOffset() + f.getBody().getNumAddresses())
                    break;
                if (ref.getReferenceType().isCall()) {
                    String target = ref.getToAddress().toString();
                    if (!seen.contains(target)) {
                        seen.add(target);
                        Function targetFunc = currentProgram.getFunctionManager().getFunctionAt(ref.getToAddress());
                        String name = targetFunc != null ? targetFunc.getName() : "???";
                        println("  -> " + target + " " + name);
                    }
                }
            }
        }
        d.dispose();
    }
}
