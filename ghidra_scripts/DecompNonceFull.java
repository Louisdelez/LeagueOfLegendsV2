import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;
public class DecompNonceFull extends GhidraScript {
    public void run() throws Exception {
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        Address addr = currentProgram.getAddressFactory().getAddress("140577f10");
        Function f = currentProgram.getFunctionManager().getFunctionAt(addr);
        println("=== FUN_140577f10 FULL (" + f.getBody().getNumAddresses() + " bytes) ===");
        DecompileResults r = d.decompileFunction(f, 120, monitor);
        if (r.decompileCompleted()) {
            for (String line : r.getDecompiledFunction().getC().split("\n"))
                println(line);
        }
        // Also dump the assembly to see EXACT byte access patterns
        println("\n=== ASSEMBLY (first 80 instructions) ===");
        Instruction inst = currentProgram.getListing().getInstructionAt(addr);
        int count = 0;
        while (inst != null && count < 80) {
            println(inst.getAddress() + ": " + inst);
            inst = inst.getNext();
            count++;
        }
        d.dispose();
    }
}
