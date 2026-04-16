import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
public class DisasmCertCall extends GhidraScript {
    public void run() throws Exception {
        // Disasm around the call to FUN_1410fbdc0 at 0x14072c26c
        println("=== Disasm around CALL FUN_1410fbdc0 at 14072c26c ===");
        for (long a = 0x14072c250L; a < 0x14072c290L; ) {
            Address addr = currentProgram.getAddressFactory().getAddress(String.format("%x", a));
            Instruction inst = currentProgram.getListing().getInstructionAt(addr);
            if (inst != null) { println("  " + addr + ": " + inst); a += inst.getLength(); } else a++;
        }
        // Also find what param_1 is - check the function entry
        println("\n=== Function entry FUN_14072c1f0 ===");
        for (long a = 0x14072c1f0L; a < 0x14072c230L; ) {
            Address addr = currentProgram.getAddressFactory().getAddress(String.format("%x", a));
            Instruction inst = currentProgram.getListing().getInstructionAt(addr);
            if (inst != null) { println("  " + addr + ": " + inst); a += inst.getLength(); } else a++;
        }
        println("=== DONE ===");
    }
}
