import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class Read128 extends GhidraScript {
    @Override
    public void run() throws Exception {
        // plVar15+0x128 contains 0x7ff7b57d77a8 (runtime)
        // base = 0x7FF7B3E90000
        // RVA = 0x7ff7b57d77a8 - 0x7FF7B3E90000 = 0x1EE77A8
        // But also: plVar15 at runtime = 0x...something... different each run
        
        // Actually plVar15+0x128 is relative to a HEAP object
        // *(plVar15 + 0x128) points to SOME address
        // In the hook log: +0x128=00007ff7b57d77a8
        // This is in the binary's image range, not heap!
        
        // RVA = 0x7ff7b57d77a8 - (0x7ff7b4403160 - 0x573160)
        //     = 0x7ff7b57d77a8 - 0x7ff7b3e90000
        //     = 0x1EE77A8
        
        long rva = 0x1EE77A8L;
        Address addr = currentProgram.getAddressFactory().getAddress(
            Long.toHexString(0x140000000L + rva));
        
        println("=== Reading at " + addr + " (RVA 0x" + Long.toHexString(rva) + ") ===");
        
        // Read 16 bytes
        byte[] data = new byte[16];
        currentProgram.getMemory().getBytes(addr, data);
        StringBuilder hex = new StringBuilder();
        for (byte b : data) hex.append(String.format("%02X ", b & 0xFF));
        println("Bytes: " + hex);
        
        // Read as qword (little-endian)
        long val = 0;
        for (int j = 7; j >= 0; j--) val = (val << 8) | (data[j] & 0xFF);
        println("*(addr) as qword = 0x" + Long.toHexString(val));
        long rvaVal = val - 0x140000000L;
        println("RVA = 0x" + Long.toHexString(rvaVal));
        
        Function fn = currentProgram.getFunctionManager().getFunctionAt(
            currentProgram.getAddressFactory().getAddress(Long.toHexString(val)));
        println("Function: " + (fn != null ? fn.getName() : "none"));
        
        // Maybe the address IS the function itself (not a vtable)
        // The consumer does (**(code**)(*plVar3 + 0x10))
        // If *plVar3 points to .rdata, then *(rdata+0x10) would be a function pointer
        // Let's try: read *(val) and *(val+0x10)
        Address fnAddr = currentProgram.getAddressFactory().getAddress(Long.toHexString(val));
        byte[] fn0 = new byte[8];
        byte[] fn10 = new byte[8];
        try {
            currentProgram.getMemory().getBytes(fnAddr, fn0);
            currentProgram.getMemory().getBytes(fnAddr.add(0x10), fn10);
            long v0 = 0, v10 = 0;
            for (int j = 7; j >= 0; j--) { v0 = (v0 << 8) | (fn0[j] & 0xFF); v10 = (v10 << 8) | (fn10[j] & 0xFF); }
            println("*(" + Long.toHexString(val) + ") = 0x" + Long.toHexString(v0));
            println("*(" + Long.toHexString(val) + "+0x10) = 0x" + Long.toHexString(v10) + 
                    " (RVA 0x" + Long.toHexString(v10 - 0x140000000L) + ")");
            Function dispFn = currentProgram.getFunctionManager().getFunctionAt(
                currentProgram.getAddressFactory().getAddress(Long.toHexString(v10)));
            if (dispFn != null) {
                println("DISPATCH FN: " + dispFn.getName() + " at " + dispFn.getEntryPoint() + 
                        " size=" + dispFn.getBody().getNumAddresses());
                DecompInterface decomp = new DecompInterface();
                decomp.openProgram(currentProgram);
                DecompileResults r = decomp.decompileFunction(dispFn, 300, monitor);
                if (r.decompileCompleted()) {
                    String[] lines = r.getDecompiledFunction().getC().split("\n");
                    println("Lines: " + lines.length);
                    for (int i = 0; i < Math.min(100, lines.length); i++) println(lines[i]);
                }
                decomp.dispose();
            }
        } catch (Exception e) {
            println("Error reading: " + e.getMessage());
            // If val is in .text, it might be a function address directly
            // Maybe the consumer doesn't do *(plVar3), it does something else
            println("val might be in .text - trying as function:");
            fn = currentProgram.getFunctionManager().getFunctionContaining(fnAddr);
            if (fn != null) {
                println("  Contains: " + fn.getName() + " at " + fn.getEntryPoint());
            }
        }
        
        println("\n=== DONE ===");
    }
}
