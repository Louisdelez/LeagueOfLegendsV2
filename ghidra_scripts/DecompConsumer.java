import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;

public class DecompConsumer extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // The consumer reads from the queue at plVar15+0x78 (slot array)
        // and is signaled via condition variable at plVar15+0x98
        // FUN_1418555d0 signals the condvar. Find who WAITS on it.
        
        // Search for calls to FUN_140566610 (copy data TO slot) - the producer
        // And search for the REVERSE: reading FROM slot array
        
        // The consumer likely calls a function that:
        // 1. Waits on condvar (FUN_1418555xx)
        // 2. Reads from slot array
        // 3. Dispatches based on command type
        
        // Let's find xrefs to FUN_140589a90 (the producer/enqueue function)
        // The consumer is probably in the same class/module
        
        println("=== Xrefs to FUN_140589a90 (producer) ===");
        Address prod = currentProgram.getAddressFactory().getAddress("140589a90");
        for (var ref : currentProgram.getReferenceManager().getReferencesTo(prod)) {
            Function caller = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
            println("  From: " + ref.getFromAddress() + 
                    (caller != null ? " in " + caller.getName() + " at " + caller.getEntryPoint() : ""));
        }
        
        // Search for xrefs to FUN_1418555d0 (condvar signal) to find the wait counterpart
        println("\n=== Xrefs to FUN_1418555d0 (condvar signal) ===");
        Address sig = currentProgram.getAddressFactory().getAddress("1418555d0");
        for (var ref : currentProgram.getReferenceManager().getReferencesTo(sig)) {
            Function caller = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
            if (caller != null && caller.getEntryPoint().getOffset() > 0x140560000L && 
                caller.getEntryPoint().getOffset() < 0x140600000L) {
                println("  From: " + ref.getFromAddress() + " in " + caller.getName() + 
                        " at " + caller.getEntryPoint() + " size=" + caller.getBody().getNumAddresses());
            }
        }
        
        // Decompile FUN_1405951d0 (called to grow queue in producer) - might lead us to consumer
        println("\n=== FUN_1405951d0 (queue grow) xrefs ===");
        Address grow = currentProgram.getAddressFactory().getAddress("1405951d0");
        for (var ref : currentProgram.getReferenceManager().getReferencesTo(grow)) {
            Function caller = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
            if (caller != null) {
                println("  From: " + ref.getFromAddress() + " in " + caller.getName() + 
                        " at " + caller.getEntryPoint());
            }
        }

        // The consumer likely has a loop that reads plVar15+0x90 (count) and processes items
        // Let's search for functions that decrement the count or read from the slot array
        // The slot array is accessed via *(plVar15+0x78)
        // Search for references to offset 0x90 being decremented
        
        // Actually, let's just decompile the function at FUN_140573160 (the vtable handler)
        // and its callers to find the consumer
        println("\n=== Xrefs to FUN_140573160 (vtable handler) ===");
        Address vh = currentProgram.getAddressFactory().getAddress("140573160");
        for (var ref : currentProgram.getReferenceManager().getReferencesTo(vh)) {
            println("  From: " + ref.getFromAddress());
        }
        
        // Decompile FUN_140595570 (called at end of FUN_140589a90 error path)
        // This might be related to the consumer
        
        // Better approach: find the function that calls FUN_14057af90 (the type 0x01/0x02 reader)
        // This is likely the consumer that processes queued data
        println("\n=== Xrefs to FUN_14057af90 (packet processor) ===");
        Address pp = currentProgram.getAddressFactory().getAddress("14057af90");
        for (var ref : currentProgram.getReferenceManager().getReferencesTo(pp)) {
            Function caller = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
            if (caller != null) {
                println("  From: " + ref.getFromAddress() + " in " + caller.getName() + 
                        " at " + caller.getEntryPoint() + " size=" + caller.getBody().getNumAddresses());
                // Decompile the caller
                DecompileResults r = decomp.decompileFunction(caller, 180, monitor);
                if (r.decompileCompleted()) {
                    String code = r.getDecompiledFunction().getC();
                    String[] lines = code.split("\n");
                    println("  Lines: " + lines.length);
                    for (int i = 0; i < Math.min(100, lines.length); i++)
                        println("  " + lines[i]);
                }
            }
        }

        println("\n=== DONE ===");
        decomp.dispose();
    }
}
