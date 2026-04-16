import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;

public class ReadVtable extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // Read vtable at RVA 0x576F2B0 (or wherever it is)
        // plVar15+0x128 points to object at (some .rdata address)
        // *(object) = vtable 
        // *(vtable+0x10) = dispatch function
        
        // The vtable address relative to image base:
        // vtable = 0x7ff7b43ff2b0, base = 0x7ff7b3e90000
        // RVA = 0x576F2B0
        long vtableRVA = 0x576F2B0L;
        Address vtAddr = currentProgram.getAddressFactory().getAddress(
            String.format("%x", 0x140000000L + vtableRVA));
        
        println("=== Vtable at " + vtAddr + " ===");
        // Read 8 function pointers from the vtable
        for (int i = 0; i < 8; i++) {
            Address slot = vtAddr.add(i * 8);
            byte[] bytes = new byte[8];
            currentProgram.getMemory().getBytes(slot, bytes);
            long val = 0;
            for (int j = 7; j >= 0; j--) val = (val << 8) | (bytes[j] & 0xFF);
            long rva = val - 0x140000000L;
            Function fn = currentProgram.getFunctionManager().getFunctionAt(
                currentProgram.getAddressFactory().getAddress(String.format("%x", val)));
            println(String.format("  [%d] +0x%02X = 0x%X (RVA 0x%X) %s",
                i, i*8, val, rva, fn != null ? fn.getName() : "???"));
            
            // Decompile the dispatch function (index 2, offset 0x10)
            if (i == 2 && fn != null) {
                println("\n=== DISPATCH FN: " + fn.getName() + " size=" + fn.getBody().getNumAddresses() + " ===");
                DecompileResults r = decomp.decompileFunction(fn, 180, monitor);
                if (r.decompileCompleted()) {
                    String code = r.getDecompiledFunction().getC();
                    for (String line : code.split("\n")) println(line);
                }
            }
        }
        
        println("\n=== DONE ===");
        decomp.dispose();
    }
}
