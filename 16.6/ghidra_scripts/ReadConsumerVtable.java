import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class ReadConsumerVtable extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // The consumer's *(param_1+0x128) object is at RVA 0x1EE77A8
        // Read its vtable and find fn+0x10
        long objRVA = 0x1EE77A8L;
        Address objAddr = currentProgram.getAddressFactory().getAddress(
            Long.toHexString(0x140000000L + objRVA));
        println("=== Consumer handler object at " + objAddr + " ===");
        
        // Read pointer (vtable)
        byte[] b = new byte[8];
        currentProgram.getMemory().getBytes(objAddr, b);
        long vtablePtr = 0;
        for (int j = 7; j >= 0; j--) vtablePtr = (vtablePtr << 8) | (b[j] & 0xFF);
        println("*(object) = vtable at 0x" + Long.toHexString(vtablePtr));
        
        // Read vtable entries
        Address vtAddr = currentProgram.getAddressFactory().getAddress(Long.toHexString(vtablePtr));
        for (int i = 0; i < 6; i++) {
            byte[] fb = new byte[8];
            currentProgram.getMemory().getBytes(vtAddr.add(i * 8), fb);
            long fnPtr = 0;
            for (int j = 7; j >= 0; j--) fnPtr = (fnPtr << 8) | (fb[j] & 0xFF);
            long rva = fnPtr - 0x140000000L;
            Function fn = currentProgram.getFunctionManager().getFunctionAt(
                currentProgram.getAddressFactory().getAddress(Long.toHexString(fnPtr)));
            println(String.format("  [%d] +0x%02X = 0x%X (RVA 0x%X) %s", 
                i, i*8, fnPtr, rva, fn != null ? fn.getName() + " size=" + fn.getBody().getNumAddresses() : "?"));
            
            // Decompile fn[2] (the dispatch at +0x10)
            if (i == 2 && fn != null) {
                println("\n=== CONSUMER GAME DISPATCH ===");
                DecompileResults r = decomp.decompileFunction(fn, 300, monitor);
                if (r.decompileCompleted()) {
                    String code = r.getDecompiledFunction().getC();
                    String[] lines = code.split("\n");
                    println("Lines: " + lines.length);
                    for (int li = 0; li < Math.min(150, lines.length); li++)
                        println(lines[li]);
                }
            }
        }
        
        println("\n=== DONE ===");
        decomp.dispose();
    }
}
