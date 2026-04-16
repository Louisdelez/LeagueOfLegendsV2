//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class DisasmBefore extends GhidraScript {
    public void run() throws Exception {
        Address base = currentProgram.getImageBase();
        // Show 200 instructions before the sendto call
        Address start = base.add(0x58EA00L);
        Address end = base.add(0x58ED00L);
        
        println("=== Disassembly 0x58EA00 - 0x58ED00 ===");
        
        // Force disassembly
        clearListing(start, end);
        disassemble(start);
        
        Address addr = start;
        while (addr.compareTo(end) < 0) {
            Instruction inst = currentProgram.getListing().getInstructionAt(addr);
            if (inst != null) {
                String mark = "";
                if (addr.equals(base.add(0x58ECB5L))) mark = " <<< SENDTO";
                if (addr.equals(base.add(0x58EC8AL))) mark = " <<< CALL before sendto";
                println(String.format("%s: %s%s", addr, inst, mark));
                addr = addr.add(inst.getLength());
            } else {
                addr = addr.add(1);
            }
        }
        println("=== DONE ===");
    }
}
