import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class CheckBase extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("Image base: " + currentProgram.getImageBase());
        println("Min addr: " + currentProgram.getMinAddress());
        println("Max addr: " + currentProgram.getMaxAddress());
        // Try to find the vtable at known handler address
        // We know vtable+0x28 points to 0x573160 (confirmed)
        // So vtable is at some address where *(addr+0x28) == imageBase + 0x573160
        long target = currentProgram.getImageBase().getOffset() + 0x573160L;
        println("Looking for vtable entry pointing to 0x" + Long.toHexString(target));
        // The vtable for the recv handler was at runtime 0x7ff7b57d7860
        // runtime_base for that session was 0x7ff7b3e90000 (from 0x7ff7b4403160 - 0x573160)  
        // No wait, base = 0x7ff7b4403160 - 0x573160 = 0x7FF7B3E90000
        // vtable runtime = 0x7ff7b57d7860
        // vtable RVA = 0x7ff7b57d7860 - 0x7FF7B3E90000 = 0x18EE860... way too large
        // Hmm, the vtable is NOT in the main binary. It might be in a DLL or heap.
        
        // Actually, the vtable 0x7ff7b57d7860 might be in the binary's .rdata section
        // Let me check: the binary is ~250MB, so .rdata could extend to very high RVAs
        long vtableRVA = 0x7ff7b57d7860L - 0x7FF7B3E90000L;
        println("Vtable RVA: 0x" + Long.toHexString(vtableRVA));
        Address vtInGhidra = currentProgram.getAddressFactory().getAddress(
            Long.toHexString(currentProgram.getImageBase().getOffset() + vtableRVA));
        println("Vtable in Ghidra: " + vtInGhidra);
        try {
            byte[] b = new byte[8];
            currentProgram.getMemory().getBytes(vtInGhidra, b);
            long val = 0;
            for (int j = 7; j >= 0; j--) val = (val << 8) | (b[j] & 0xFF);
            println("*(vtable) = 0x" + Long.toHexString(val));
        } catch (Exception e) {
            println("Can't read vtable: " + e.getMessage());
        }
        
        println("=== DONE ===");
    }
}
