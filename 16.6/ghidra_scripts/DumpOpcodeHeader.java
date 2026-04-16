//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

/**
 * DumpOpcodeHeader - Get the first part of FUN_140955c20 to see how the opcode is read
 */
public class DumpOpcodeHeader extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        Function f = getFunctionAt(toAddr(0x140955c20L));
        if (f == null) { println("No function"); return; }

        DecompileResults r = decomp.decompileFunction(f, 600, monitor);
        if (r.decompileCompleted()) {
            String[] lines = r.getDecompiledFunction().getC().split("\n");
            // Print first 100 lines to see the opcode extraction
            for (int i = 0; i < Math.min(100, lines.length); i++) {
                println(String.format("[%d] %s", i, lines[i]));
            }
        }

        // Also get callers
        println("\n=== CALLERS ===");
        for (var ref : getReferencesTo(f.getEntryPoint())) {
            Function caller = getFunctionContaining(ref.getFromAddress());
            if (caller != null) {
                println("  " + caller.getName() + "@" + caller.getEntryPoint() +
                    " size=" + caller.getBody().getNumAddresses());
            } else {
                println("  Data ref at " + ref.getFromAddress());
            }
        }

        // Disassemble first 50 bytes to see the opcode read
        println("\n=== DISASM (first instructions) ===");
        long addr = 0x140955c20L;
        for (int i = 0; i < 30; i++) {
            Address a = toAddr(addr);
            Instruction inst = currentProgram.getListing().getInstructionAt(a);
            if (inst != null) {
                println("  " + a + ": " + inst);
                addr += inst.getLength();
            } else break;
        }

        println("\n=== DONE ===");
        decomp.dispose();
    }
}
