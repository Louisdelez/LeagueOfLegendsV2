import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import java.util.*;

public class DecompBatchFraming extends GhidraScript {

    private DecompInterface decomp;
    private Set<String> decompiled = new HashSet<>();

    private void decompFunc(String label, String addrStr) throws Exception {
        if (decompiled.contains(addrStr)) return;
        decompiled.add(addrStr);
        Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
        Function func = currentProgram.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = currentProgram.getFunctionManager().getFunctionContaining(addr);
        }
        if (func == null) {
            println("=== " + label + " at " + addrStr + " — NO FUNCTION FOUND ===");
            return;
        }
        println("=== " + label + ": " + func.getName() + " at " + func.getEntryPoint() +
                " size=" + func.getBody().getNumAddresses() + " ===");
        DecompileResults r = decomp.decompileFunction(func, 300, monitor);
        if (r.decompileCompleted()) {
            for (String line : r.getDecompiledFunction().getC().split("\n"))
                println(line);
        } else {
            println("DECOMPILE FAILED");
        }
        println("");
    }

    private void decompFuncAndCallees(String label, String addrStr, int depth) throws Exception {
        if (depth < 0 || decompiled.contains(addrStr)) return;
        decompFunc(label, addrStr);

        if (depth > 0) {
            Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
            Function func = currentProgram.getFunctionManager().getFunctionAt(addr);
            if (func == null) func = currentProgram.getFunctionManager().getFunctionContaining(addr);
            if (func == null) return;

            Set<Function> called = func.getCalledFunctions(monitor);
            for (Function callee : called) {
                long off = callee.getEntryPoint().getOffset();
                // Skip thunks, CRT, and very large functions
                if (off < 0x140500000L || off > 0x141000000L) continue;
                String calleeAddr = String.format("%x", off);
                if (!decompiled.contains(calleeAddr)) {
                    decompFunc("callee of " + label, calleeAddr);
                }
            }
        }
    }

    @Override
    public void run() throws Exception {
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // 1. The main consumer: FUN_1405883d0
        println("############################################");
        println("# PART 1: CONSUMER FUN_1405883d0 (dequeue+dispatch)");
        println("############################################");
        decompFuncAndCallees("CONSUMER", "1405883d0", 1);

        // 2. The enqueue function to understand struct layout
        println("############################################");
        println("# PART 2: ENQUEUE FUN_140573160 (vtable+0x28)");
        println("############################################");
        decompFunc("ENQUEUE", "140573160");

        // 3. Functions around consumer that handle cmd types
        // FUN_1405897f0 and FUN_140589970 from DecompConsumer2
        println("############################################");
        println("# PART 3: CMD HANDLER FUNCTIONS");
        println("############################################");
        decompFunc("CMD_HANDLER_1", "1405897f0");
        decompFunc("CMD_HANDLER_2", "140589970");

        // 4. The packet processor FUN_14057af90
        println("############################################");
        println("# PART 4: PACKET PROCESSOR FUN_14057af90");
        println("############################################");
        decompFuncAndCallees("PKT_PROCESSOR", "14057af90", 1);

        // 5. The cmd dispatch function containing CMP CL,3 at 0x140589cb5
        println("############################################");
        println("# PART 5: CMD DISPATCH (contains CMP CL,3)");
        println("############################################");
        decompFunc("CMD_DISPATCH", "140589cb5");

        // 6. FUN_140589fc0 (type 0x01 reader mentioned previously)
        println("############################################");
        println("# PART 6: TYPE_01_READER FUN_140589fc0");
        println("############################################");
        decompFunc("TYPE_01_READER", "140589fc0");

        // 7. Game dispatcher FUN_140955c20 (reads opcode at param_2+0x08)
        println("############################################");
        println("# PART 7: GAME DISPATCHER FUN_140955c20");
        println("############################################");
        decompFunc("GAME_DISPATCHER", "140955c20");

        // 8. Find who calls FUN_140955c20 to understand the struct passed to it
        println("############################################");
        println("# PART 8: CALLERS OF GAME DISPATCHER");
        println("############################################");
        Address dispAddr = currentProgram.getAddressFactory().getAddress("140955c20");
        for (Reference ref : currentProgram.getReferenceManager().getReferencesTo(dispAddr)) {
            Function caller = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
            if (caller != null) {
                println("Caller from " + ref.getFromAddress() + " in " + caller.getName() +
                        " at " + caller.getEntryPoint());
                decompFunc("DISPATCHER_CALLER", String.format("%x", caller.getEntryPoint().getOffset()));
            }
        }

        // 9. Also look at FUN_140571d80 (from DecompConsumer2 - may be queue read)
        println("############################################");
        println("# PART 9: QUEUE READ FUN_140571d80");
        println("############################################");
        decompFunc("QUEUE_READ", "140571d80");

        println("\n=== ALL DONE ===");
        decomp.dispose();
    }
}
