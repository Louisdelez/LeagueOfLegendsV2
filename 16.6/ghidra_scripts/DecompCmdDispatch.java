import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;

public class DecompCmdDispatch extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // 1. Decompile function containing CMP CL,0x3 at 0x140589cb5
        Address cmdCheck = currentProgram.getAddressFactory().getAddress("140589cb5");
        Function cmdFunc = currentProgram.getFunctionManager().getFunctionContaining(cmdCheck);
        if (cmdFunc != null) {
            println("=== CMD DISPATCH FUNCTION: " + cmdFunc.getName() + " at " + cmdFunc.getEntryPoint() +
                    " size=" + cmdFunc.getBody().getNumAddresses() + " ===");
            DecompileResults result = decomp.decompileFunction(cmdFunc, 180, monitor);
            if (result.decompileCompleted()) {
                String code = result.getDecompiledFunction().getC();
                String[] lines = code.split("\n");
                println("Lines: " + lines.length);
                for (String line : lines) println(line);
            }
        } else {
            println("No function at 140589cb5!");
            // Show disassembly around
            for (long a = 0x140589ca0L; a < 0x140589d20L; ) {
                Address addr = currentProgram.getAddressFactory().getAddress(String.format("%x", a));
                Instruction inst = currentProgram.getListing().getInstructionAt(addr);
                if (inst != null) {
                    println("  " + addr + ": " + inst);
                    a += inst.getLength();
                } else a++;
            }
        }

        // 2. Also decompile FUN_140589fc0 (type 0x01 reader) to understand framing
        println("\n=== FUN_140589fc0 (Type 0x01 reader) ===");
        Address f9fc0 = currentProgram.getAddressFactory().getAddress("140589fc0");
        Function func9fc0 = currentProgram.getFunctionManager().getFunctionContaining(f9fc0);
        if (func9fc0 != null) {
            println("Function: " + func9fc0.getName() + " size=" + func9fc0.getBody().getNumAddresses());
            DecompileResults result = decomp.decompileFunction(func9fc0, 180, monitor);
            if (result.decompileCompleted()) {
                for (String line : result.getDecompiledFunction().getC().split("\n")) println(line);
            }
        }

        // 3. Disassemble around 0x589cb5 for context
        println("\n=== Disasm around CMP CL,3 ===");
        for (long a = 0x140589c90L; a < 0x140589d30L; ) {
            Address addr = currentProgram.getAddressFactory().getAddress(String.format("%x", a));
            Instruction inst = currentProgram.getListing().getInstructionAt(addr);
            if (inst != null) {
                println("  " + addr + ": " + inst);
                a += inst.getLength();
            } else a++;
        }

        println("\n=== DONE ===");
        decomp.dispose();
    }
}
