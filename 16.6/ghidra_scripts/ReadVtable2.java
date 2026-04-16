import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;

public class ReadVtable2 extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        Address vtAddr = currentProgram.getAddressFactory().getAddress("141947860");
        println("=== Consumer Vtable at " + vtAddr + " ===");
        for (int i = 0; i < 6; i++) {
            Address slot = vtAddr.add(i * 8);
            byte[] bytes = new byte[8];
            currentProgram.getMemory().getBytes(slot, bytes);
            long val = 0;
            for (int j = 7; j >= 0; j--) val = (val << 8) | (bytes[j] & 0xFF);
            long rva = val - 0x140000000L;
            Function fn = currentProgram.getFunctionManager().getFunctionAt(
                currentProgram.getAddressFactory().getAddress(String.format("%x", val)));
            println(String.format("  [%d] +0x%02X = 0x%X (RVA 0x%X) %s",
                i, i*8, val, rva, fn != null ? fn.getName() + " size=" + fn.getBody().getNumAddresses() : "?"));
        }

        // Decompile vtable[2] (offset +0x10) — the consumer dispatch
        Address fn2Addr = vtAddr.add(0x10);
        byte[] fn2Bytes = new byte[8];
        currentProgram.getMemory().getBytes(fn2Addr, fn2Bytes);
        long fn2Val = 0;
        for (int j = 7; j >= 0; j--) fn2Val = (fn2Val << 8) | (fn2Bytes[j] & 0xFF);
        
        Function dispatchFn = currentProgram.getFunctionManager().getFunctionAt(
            currentProgram.getAddressFactory().getAddress(String.format("%x", fn2Val)));
        if (dispatchFn != null) {
            println("\n=== DISPATCH: " + dispatchFn.getName() + " at " + dispatchFn.getEntryPoint() +
                    " size=" + dispatchFn.getBody().getNumAddresses() + " ===");
            DecompileResults r = decomp.decompileFunction(dispatchFn, 300, monitor);
            if (r.decompileCompleted()) {
                for (String line : r.getDecompiledFunction().getC().split("\n"))
                    println(line);
            }
        } else {
            println("No function at dispatch address 0x" + Long.toHexString(fn2Val));
        }

        println("\n=== DONE ===");
        decomp.dispose();
    }
}
