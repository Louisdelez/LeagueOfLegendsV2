import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;

public class DecompDispatch extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        Address addr = currentProgram.getAddressFactory().getAddress("1405728a0");
        Function fn = currentProgram.getFunctionManager().getFunctionContaining(addr);
        if (fn == null) fn = currentProgram.getFunctionManager().getFunctionAt(addr);
        if (fn == null) {
            println("Creating function at 1405728a0...");
            fn = currentProgram.getFunctionManager().createFunction("CONSUMER_DISPATCH",
                addr, new AddressSet(addr, addr.add(0x200)), SourceType.USER_DEFINED);
            fn = currentProgram.getFunctionManager().getFunctionContaining(addr);
        }
        
        if (fn != null) {
            println("=== " + fn.getName() + " at " + fn.getEntryPoint() + 
                    " size=" + fn.getBody().getNumAddresses() + " ===");
            DecompileResults r = decomp.decompileFunction(fn, 300, monitor);
            if (r.decompileCompleted()) {
                for (String line : r.getDecompiledFunction().getC().split("\n"))
                    println(line);
            } else {
                println("Decompile failed: " + r.getErrorMessage());
                // Fallback: disassembly
                for (long a = 0x1405728a0L; a < 0x140572a00L; ) {
                    Address ia = currentProgram.getAddressFactory().getAddress(String.format("%x", a));
                    Instruction inst = currentProgram.getListing().getInstructionAt(ia);
                    if (inst != null) {
                        println("  " + ia + ": " + inst);
                        a += inst.getLength();
                    } else a++;
                }
            }
        }
        println("\n=== DONE ===");
        decomp.dispose();
    }
}
