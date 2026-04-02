import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class FindAt5728a0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        Address addr = currentProgram.getAddressFactory().getAddress("1405728a0");
        Function fn = currentProgram.getFunctionManager().getFunctionContaining(addr);
        if (fn != null) {
            println("=== CONTAINING: " + fn.getName() + " at " + fn.getEntryPoint() + " size=" + fn.getBody().getNumAddresses() + " ===");
            DecompileResults r = decomp.decompileFunction(fn, 300, monitor);
            if (r.decompileCompleted()) { for (String l : r.getDecompiledFunction().getC().split("\n")) println(l); }
        } else {
            println("No function contains 1405728a0. Disasm:");
            for (long a = 0x1405728a0L; a < 0x140572990L; ) {
                Address ia = currentProgram.getAddressFactory().getAddress(String.format("%x", a));
                Instruction inst = currentProgram.getListing().getInstructionAt(ia);
                if (inst != null) { println("  " + ia + ": " + inst); a += inst.getLength(); } else a++;
            }
        }
        println("=== DONE ===");
        decomp.dispose();
    }
}
