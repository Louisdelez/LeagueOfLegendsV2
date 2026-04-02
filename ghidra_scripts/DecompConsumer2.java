import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;

public class DecompConsumer2 extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        String[] addrs = {"1405897f0", "140589970", "1405883d0", "140571d80"};
        for (String a : addrs) {
            Address addr = currentProgram.getAddressFactory().getAddress(a);
            Function func = currentProgram.getFunctionManager().getFunctionAt(addr);
            if (func != null) {
                println("=== " + func.getName() + " at " + func.getEntryPoint() +
                        " size=" + func.getBody().getNumAddresses() + " ===");
                DecompileResults r = decomp.decompileFunction(func, 180, monitor);
                if (r.decompileCompleted()) {
                    for (String line : r.getDecompiledFunction().getC().split("\n"))
                        println(line);
                }
                println("");
            }
        }
        println("=== DONE ===");
        decomp.dispose();
    }
}
