import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;

public class ForceDecomp58B extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // Dump disassembly from 0x58AEE0 to 0x58B300
        println("=== DISASSEMBLY 14058aee0 - 14058b300 ===");
        for (long addr = 0x14058aee0L; addr < 0x14058b300L; ) {
            Address a = currentProgram.getAddressFactory().getAddress(String.format("%x", addr));
            Instruction inst = currentProgram.getListing().getInstructionAt(a);
            if (inst != null) {
                println(String.format("  %s: %s", a, inst));
                addr += inst.getLength();
            } else {
                addr++;
            }
        }

        // Look for function prologue scanning backwards from recvfrom call
        println("\n=== Function prologue search ===");
        for (long addr = 0x14058b090L; addr > 0x14058ae00L; addr--) {
            Address a = currentProgram.getAddressFactory().getAddress(String.format("%x", addr));
            Instruction inst = currentProgram.getListing().getInstructionAt(a);
            if (inst != null && inst.toString().contains("SUB RSP")) {
                println(String.format("  SUB RSP at %s: %s", a, inst));
            }
        }

        // Check function pointer tables
        println("\n=== Key function pointers ===");
        long[] ptrs = {0x1418dfd20L, 0x1418dfd10L, 0x1418dfd18L, 0x1418dfd28L};
        String[] names = {"recvfrom?", "CRC_nonce", "unknown-8", "unknown+8"};
        for (int i = 0; i < ptrs.length; i++) {
            Address pa = currentProgram.getAddressFactory().getAddress(String.format("%x", ptrs[i]));
            try {
                byte[] b = new byte[8];
                currentProgram.getMemory().getBytes(pa, b);
                long val = 0;
                for (int j = 7; j >= 0; j--) val = (val << 8) | (b[j] & 0xFF);
                println(String.format("  [%s] 0x%X = 0x%X", names[i], ptrs[i], val));
            } catch (Exception e) {
                println(String.format("  [%s] 0x%X = ERROR: %s", names[i], ptrs[i], e.getMessage()));
            }
        }

        // Check Xrefs to FUN_140588f70
        println("\n=== Xrefs to FUN_140588f70 ===");
        Address f588 = currentProgram.getAddressFactory().getAddress("140588f70");
        for (var ref : currentProgram.getReferenceManager().getReferencesTo(f588)) {
            println("  From: " + ref.getFromAddress());
        }

        println("\n=== DONE ===");
        decomp.dispose();
    }
}
