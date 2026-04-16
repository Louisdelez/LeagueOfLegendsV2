//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;

public class FindEnqueueWrite extends GhidraScript {
    public void run() throws Exception {
        Address base = currentProgram.getImageBase();
        println("=== Finding enqueue function (writes to circular buffer queue) ===");

        // The send loop NET_58e860 reads from a queue:
        //   queue_base = *(param_1 + 0xB8)
        //   queue_index = *(param_1 + 0xC0)
        //   queue_mask = *(param_1 + 0xC8)
        //   entry_ptr = queue_base + ((queue_index - 1) & queue_mask) * 8
        //
        // The dequeue function FUN_140596260 advances the index at param_1 + 0xB0
        //
        // The ENQUEUE function must:
        //   1. Write data to the queue
        //   2. Increment the queue count at param_1 + 0xD0 (or similar)
        //   3. Signal the send thread
        //
        // FUN_140596260 (dequeue) is at 0x596260
        // Let's find functions that call the OPPOSITE operation (enqueue/push)

        // Strategy: Find all callers of the condition variable signal
        // FUN_1418555E8 is called in the send loop: FUN_1418555e8(param_1 + 0xd8, lVar7)
        // This is likely a condition variable Wait
        // The enqueue will call the corresponding Signal/Notify

        // Let's look at FUN_1418555D0 which is also called: FUN_1418555d0(param_1 + 0xd8)
        // This could be the signal function

        long[] signalFuncs = { 0x18555D0L, 0x1855638L, 0x18555E8L, 0x1854AD0L, 0x1854AC8L };
        String[] names = { "CondVar_Signal?", "CondVar_Broadcast?", "CondVar_Wait?", "Mutex_Lock?", "Mutex_TryLock?" };

        for (int idx = 0; idx < signalFuncs.length; idx++) {
            Address addr = base.add(signalFuncs[idx]);
            Function func = getFunctionAt(addr);
            if (func == null) continue;

            Reference[] refs = getReferencesTo(func.getEntryPoint());
            println("\n" + names[idx] + " = " + func.getName() + " at " + func.getEntryPoint() + " (" + refs.length + " callers)");

            if (refs.length < 30) {
                java.util.Set<String> seen = new java.util.HashSet<>();
                for (Reference ref : refs) {
                    Function caller = getFunctionContaining(ref.getFromAddress());
                    if (caller != null && seen.add(caller.getName())) {
                        println("  " + caller.getName() + " at " + caller.getEntryPoint());
                    }
                }
            }
        }

        // Strategy 2: Search for the constant 519 (0x207) in functions
        // The enqueue function must know the packet size
        println("\n=== Searching for 0x207 (519) in all functions ===");
        InstructionIterator iter = currentProgram.getListing().getInstructions(true);
        java.util.Set<String> funcsWithSize = new java.util.HashSet<>();
        int count = 0;

        while (iter.hasNext() && count < 50) {
            Instruction inst = iter.next();
            for (int i = 0; i < inst.getNumOperands(); i++) {
                Object[] ops = inst.getOpObjects(i);
                for (Object op : ops) {
                    if (op instanceof ghidra.program.model.scalar.Scalar) {
                        long val = ((ghidra.program.model.scalar.Scalar) op).getValue();
                        if (val == 0x207 || val == 519) {
                            Function f = getFunctionContaining(inst.getAddress());
                            if (f != null && funcsWithSize.add(f.getName())) {
                                count++;
                                println("  519 at " + inst.getAddress() + " in " + f.getName() + " (" + f.getEntryPoint() + ")");

                                // Check if this function also references the queue
                                // by looking for offsets 0xB8, 0xC0, 0xC8, 0xD0
                                boolean hasQueueRef = false;
                                for (ghidra.program.model.listing.Instruction innerInst :
                                     currentProgram.getListing().getInstructions(f.getBody(), true)) {
                                    String instStr = innerInst.toString();
                                    if (instStr.contains("0xb8") || instStr.contains("0xc0") ||
                                        instStr.contains("0xc8") || instStr.contains("0xd0")) {
                                        hasQueueRef = true;
                                        break;
                                    }
                                }
                                if (hasQueueRef) {
                                    println("    *** HAS QUEUE OFFSETS (0xB8/0xC0/0xC8/0xD0) ***");
                                    // Decompile this function
                                    ghidra.app.decompiler.DecompInterface d = new ghidra.app.decompiler.DecompInterface();
                                    d.openProgram(currentProgram);
                                    ghidra.app.decompiler.DecompileResults r = d.decompileFunction(f, 120, monitor);
                                    if (r.decompileCompleted()) {
                                        String[] lines = r.getDecompiledFunction().getC().split("\n");
                                        for (int li = 0; li < Math.min(lines.length, 200); li++) println("    " + lines[li]);
                                        if (lines.length > 200) println("    ... (" + (lines.length - 200) + " more)");
                                    }
                                    d.dispose();
                                }
                            }
                        }
                    }
                }
            }
        }

        println("\n=== DONE ===");
    }
}
