import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;

public class DecompCopy extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        String[] funcs = {"14056d410", "140566610", "140566790"};
        String[] names = {"CopyFromCRC", "CopyToSlot", "InitSlot"};
        for (int i = 0; i < funcs.length; i++) {
            Address a = currentProgram.getAddressFactory().getAddress(funcs[i]);
            Function f = currentProgram.getFunctionManager().getFunctionContaining(a);
            if (f == null) f = currentProgram.getFunctionManager().getFunctionAt(a);
            if (f != null) {
                println("=== " + names[i] + " " + f.getName() + " at " + f.getEntryPoint() +
                        " size=" + f.getBody().getNumAddresses() + " ===");
                DecompileResults r = decomp.decompileFunction(f, 180, monitor);
                if (r.decompileCompleted()) {
                    for (String line : r.getDecompiledFunction().getC().split("\n"))
                        println(line);
                }
            }
        }
        println("\n=== DONE ===");
        decomp.dispose();
    }
}
