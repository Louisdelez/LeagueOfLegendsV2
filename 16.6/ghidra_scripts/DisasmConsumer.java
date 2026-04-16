import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class DisasmConsumer extends GhidraScript {
    @Override
    public void run() throws Exception {
        // Disassemble FUN_1405883d0 around the else branch (0x128 dispatch)
        // Search for MOV with 0x128
        println("=== Disasm FUN_1405883d0 (consumer) ===");
        for (long a = 0x1405883d0L; a < 0x140588650L; ) {
            Address addr = currentProgram.getAddressFactory().getAddress(String.format("%x", a));
            Instruction inst = currentProgram.getListing().getInstructionAt(addr);
            if (inst != null) {
                String s = inst.toString();
                if (s.contains("0x128") || s.contains("0x168") || s.contains("CALL") || s.contains("0xa0") || s.contains("local_60")) {
                    println("  " + addr + ": " + s);
                }
                a += inst.getLength();
            } else a++;
        }
        println("\n=== Full disasm around dispatch ===");
        // Find the area with 0x128
        for (long a = 0x140588550L; a < 0x140588650L; ) {
            Address addr = currentProgram.getAddressFactory().getAddress(String.format("%x", a));
            Instruction inst = currentProgram.getListing().getInstructionAt(addr);
            if (inst != null) {
                println("  " + addr + ": " + inst);
                a += inst.getLength();
            } else a++;
        }
        println("=== DONE ===");
    }
}
