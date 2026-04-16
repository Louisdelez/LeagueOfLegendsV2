import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;

public class TraceRSI extends GhidraScript {
    @Override
    public void run() throws Exception {
        // Find where RSI is set before 14058b1bd (MOV RCX, RSI)
        // Search backwards for MOV RSI or LEA RSI
        println("=== Searching for RSI assignments before 14058b1bd ===");
        for (long a = 0x14058b1bcL; a > 0x14058ae00L; a--) {
            Address addr = currentProgram.getAddressFactory().getAddress(String.format("%x", a));
            Instruction inst = currentProgram.getListing().getInstructionAt(addr);
            if (inst != null) {
                String s = inst.toString();
                if ((s.contains("MOV") || s.contains("LEA")) && s.contains("RSI")) {
                    println(String.format("  %s: %s", addr, inst));
                }
            }
        }

        // Also check the function entry to see if RSI is a parameter
        println("\n=== Function entry area (14058af30-14058af80) ===");
        for (long a = 0x14058af30L; a < 0x14058af80L; ) {
            Address addr = currentProgram.getAddressFactory().getAddress(String.format("%x", a));
            Instruction inst = currentProgram.getListing().getInstructionAt(addr);
            if (inst != null) {
                println(String.format("  %s: %s", addr, inst));
                a += inst.getLength();
            } else a++;
        }

        println("\n=== DONE ===");
    }
}
