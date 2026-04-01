import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;

public class ForceDecomp58B extends GhidraScript {
    public void run() throws Exception {
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);

        // Show instructions around the recvfrom call at 14058b093
        println("=== INSTRUCTIONS AROUND recvfrom CALL (14058b080-14058b120) ===");
        Address start = currentProgram.getAddressFactory().getAddress("14058b050");
        Instruction inst = currentProgram.getListing().getInstructionAfter(start);
        while (inst != null && inst.getAddress().getOffset() < 0x14058b150L) {
            println("  " + inst.getAddress() + ": " + inst);
            inst = inst.getNext();
        }

        // Try to find the real function start by scanning backwards for a common prologue
        println("\n=== SCANNING BACKWARDS FOR FUNCTION START ===");
        for (long addr = 0x14058b080L; addr >= 0x14058af00L; addr--) {
            Address a = currentProgram.getAddressFactory().getAddress(String.format("%x", addr));
            inst = currentProgram.getListing().getInstructionAt(a);
            if (inst != null) {
                String mnemonic = inst.getMnemonicString();
                // Common function prologues: PUSH, SUB RSP, MOV [RSP+...], LEA
                if (mnemonic.equals("PUSH") || mnemonic.startsWith("SUB") || 
                    (mnemonic.equals("MOV") && inst.toString().contains("RSP"))) {
                    println("  Possible prologue at " + a + ": " + inst);
                }
            }
        }

        // Try creating function at some candidate addresses
        long[] candidates = {0x14058af20L, 0x14058af30L, 0x14058af40L, 0x14058af50L, 
                            0x14058af60L, 0x14058af80L, 0x14058afa0L, 0x14058afc0L,
                            0x14058afe0L, 0x14058b000L, 0x14058b020L, 0x14058b040L,
                            0x14058b060L, 0x14058b070L};
        for (long c : candidates) {
            Address ca = currentProgram.getAddressFactory().getAddress(String.format("%x", c));
            try {
                Function f = createFunction(ca, null);
                if (f != null && f.getBody().getNumAddresses() > 50) {
                    println("\n=== CREATED FUNCTION at " + ca + " size=" + f.getBody().getNumAddresses() + " ===");
                    // Check if it contains our target
                    if (f.getBody().contains(currentProgram.getAddressFactory().getAddress("14058b093"))) {
                        println("*** CONTAINS recvfrom call! ***");
                        DecompileResults r = d.decompileFunction(f, 120, monitor);
                        if (r.decompileCompleted()) {
                            String[] lines = r.getDecompiledFunction().getC().split("\n");
                            println("Lines: " + lines.length);
                            for (String line : lines) println(line);
                        }
                    }
                }
            } catch (Exception e) {
                // Skip
            }
        }

        println("\n=== DONE ===");
        d.dispose();
    }
}
