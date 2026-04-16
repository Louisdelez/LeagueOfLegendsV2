//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.MemoryAccessException;
import java.util.*;

/**
 * FindOpcodeTable4 - Find vtable for ENet host, trace data handlers to game opcode dispatch
 *
 * FUN_14057e7f0 dispatches ENet commands via vtable:
 *   type 5 -> vtable+0x30 (reliable data)
 *   type 6 -> vtable+0x38 (unreliable data)
 *   type 7 -> vtable+0x40 (fragment)
 *   type 8 -> vtable+0x48 (unsequenced)
 *
 * Need to find the actual vtable, then follow the data handler chain to the game opcode dispatch.
 */
public class FindOpcodeTable4 extends GhidraScript {

    private DecompInterface decomp;

    @Override
    public void run() throws Exception {
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // Phase 1: Find the vtable by looking at xrefs to FUN_14057e7f0
        // param_2 in FUN_14057e7f0 is the object whose vtable we need
        // This object is created/initialized somewhere - find where *param_2 (the vtable ptr) is set
        println("=== Phase 1: Finding the ENet host vtable ===");

        // The caller of FUN_14057e7f0 passes param_2 as a pointer to the host object
        // FUN_14057e910 calls FUN_14057e7f0(param_1, *puVar15, param_2)
        // So the host object is at *puVar15 which comes from param_1 (the ENet peer/host)

        // Let's find vtables in the .rdata section that have exactly the right layout:
        // offset 0x08: acknowledge handler
        // offset 0x10: connect handler
        // offset 0x18: verify_connect handler
        // etc.

        // Strategy: Look for FUN_14057dce0 (our known handler) in the vtable
        // FUN_14057dce0 is called at vtable+0x160 according to the user
        // Let's search for any .rdata address that stores 0x14057dce0

        println("Searching for vtable containing FUN_14057dce0...");
        Address targetAddr = currentProgram.getAddressFactory().getAddress("14057dce0");
        for (Reference ref : getReferencesTo(targetAddr)) {
            Address from = ref.getFromAddress();
            if (ref.getReferenceType().isData()) {
                println("  DATA ref to 14057dce0 at " + from);
                // Read surrounding memory to see if this is a vtable
                try {
                    long base = from.getOffset();
                    // Read a few entries around this address
                    for (int i = -5; i <= 5; i++) {
                        long entryAddr = base + (i * 8);
                        Address ea = currentProgram.getAddressFactory().getAddress(String.format("%x", entryAddr));
                        long val = currentProgram.getMemory().getLong(ea);
                        Function f = currentProgram.getFunctionManager().getFunctionAt(
                            currentProgram.getAddressFactory().getAddress(String.format("%x", val)));
                        println(String.format("    [%+d] 0x%X -> 0x%X %s", i,
                            entryAddr, val, f != null ? f.getName() : "(not a function)"));
                    }
                } catch (Exception e) {
                    println("    (read error: " + e.getMessage() + ")");
                }
            }
        }

        // Phase 2: Also search for FUN_14057dd10 and FUN_14057dec0 in vtables
        println("\n=== Phase 2: Searching for FUN_14057dd10 in data ===");
        for (Reference ref : getReferencesTo(currentProgram.getAddressFactory().getAddress("14057dd10"))) {
            if (ref.getReferenceType().isData()) {
                println("  DATA ref at " + ref.getFromAddress());
                dumpVtableAround(ref.getFromAddress(), 10);
            }
        }

        println("\n=== Phase 2b: Searching for FUN_14057dec0 in data ===");
        for (Reference ref : getReferencesTo(currentProgram.getAddressFactory().getAddress("14057dec0"))) {
            if (ref.getReferenceType().isData()) {
                println("  DATA ref at " + ref.getFromAddress());
                dumpVtableAround(ref.getFromAddress(), 10);
            }
        }

        // Phase 3: Search for FUN_14057e7f0 refs to find what creates the handler object
        println("\n=== Phase 3: Callers of FUN_14057e7f0 ===");
        for (Reference ref : getReferencesTo(currentProgram.getAddressFactory().getAddress("14057e7f0"))) {
            Function caller = getFunctionContaining(ref.getFromAddress());
            if (caller != null) {
                println("  Called from " + ref.getFromAddress() + " in " + caller.getName() +
                        " at " + caller.getEntryPoint());
            }
        }

        // Phase 4: Where is param_1 in FUN_14057e910 initialized?
        // param_1 is the ENet host. Check what creates it.
        // The host object has a vtable at offset 0. Find where the vtable ptr is written.
        // Trace FUN_1405883d0 (consumer) which is in the pipeline
        println("\n=== Phase 4: Decompile FUN_1405883d0 (consumer) ===");
        decompFull("1405883d0", 100);

        // Phase 5: FUN_14057e7f0 reads *(int*)(param_3 + 0xc) for command type
        // and calls vtable[type]. The vtable is at *param_2.
        // param_2 is the host object. Where is its vtable set?
        // Look for constructors that set vtable pointers in the 14057xxxx range
        println("\n=== Phase 5: Search for vtable initialization in 14057-14059 range ===");
        // Look for MOV [reg], imm64 patterns where imm64 is in .rdata (vtable assignment)
        // These typically look like: LEA RAX, [rip+xxxx]; MOV [RCX], RAX
        findVtableAssignments(0x14056e000L, 0x14059a000L);

        println("\n=== DONE ===");
        decomp.dispose();
    }

    private void dumpVtableAround(Address center, int range) {
        try {
            long base = center.getOffset();
            for (int i = -range; i <= range; i++) {
                long entryAddr = base + (i * 8);
                Address ea = currentProgram.getAddressFactory().getAddress(String.format("%x", entryAddr));
                long val = currentProgram.getMemory().getLong(ea);
                if (val > 0x140000000L && val < 0x142000000L) {
                    Function f = currentProgram.getFunctionManager().getFunctionAt(
                        currentProgram.getAddressFactory().getAddress(String.format("%x", val)));
                    println(String.format("    [%+d] 0x%X -> 0x%X %s", i,
                        entryAddr, val, f != null ? f.getName() + " (size=" + f.getBody().getNumAddresses() + ")" : ""));
                }
            }
        } catch (Exception e) {
            println("    (read error)");
        }
    }

    private void decompFull(String hexAddr, int maxLines) {
        Address a = currentProgram.getAddressFactory().getAddress(hexAddr);
        Function f = currentProgram.getFunctionManager().getFunctionAt(a);
        if (f == null) f = currentProgram.getFunctionManager().getFunctionContaining(a);
        if (f == null) { println("No function at " + hexAddr); return; }
        println(f.getName() + " at " + f.getEntryPoint() + " size=" + f.getBody().getNumAddresses());
        try {
            DecompileResults r = decomp.decompileFunction(f, 300, monitor);
            if (r.decompileCompleted()) {
                String[] lines = r.getDecompiledFunction().getC().split("\n");
                for (int i = 0; i < Math.min(maxLines, lines.length); i++) println("  " + lines[i]);
                if (lines.length > maxLines) println("  ... (" + (lines.length - maxLines) + " more lines)");
            }
        } catch (Exception e) { println("  Error: " + e.getMessage()); }
    }

    private void findVtableAssignments(long start, long end) {
        // Look for LEA RAX, [addr_in_rdata]; followed by MOV [RCX/RDI], RAX
        // This is the typical vtable initialization pattern
        Set<String> seen = new HashSet<>();
        for (long off = start; off < end; ) {
            Address a = currentProgram.getAddressFactory().getAddress(String.format("%x", off));
            Instruction inst = currentProgram.getListing().getInstructionAt(a);
            if (inst != null) {
                if (inst.getMnemonicString().equals("LEA")) {
                    // Check if loading from .rdata
                    for (Reference ref : inst.getReferencesFrom()) {
                        long target = ref.getToAddress().getOffset();
                        // .rdata is typically in the higher part of the image
                        if (target > 0x141800000L && target < 0x141e00000L) {
                            // Check if the next instruction stores this to [reg]
                            Address next = a.add(inst.getLength());
                            Instruction nextInst = currentProgram.getListing().getInstructionAt(next);
                            if (nextInst != null && nextInst.getMnemonicString().equals("MOV")) {
                                String op0 = nextInst.getDefaultOperandRepresentation(0);
                                if (op0.startsWith("[") || op0.contains("qword ptr [")) {
                                    String key = String.format("%x", target);
                                    if (seen.add(key)) {
                                        Function func = getFunctionContaining(a);
                                        println(String.format("  VTABLE INIT at %s: LEA to 0x%X, stored via %s  (in %s)",
                                            a, target, nextInst,
                                            func != null ? func.getName() + "@" + func.getEntryPoint() : "?"));
                                        // Dump the vtable
                                        dumpVtable(target, 20);
                                    }
                                }
                            }
                        }
                    }
                }
                off += inst.getLength();
            } else { off++; }
        }
    }

    private void dumpVtable(long vtableAddr, int entries) {
        try {
            for (int i = 0; i < entries; i++) {
                Address ea = currentProgram.getAddressFactory().getAddress(
                    String.format("%x", vtableAddr + i * 8));
                long val = currentProgram.getMemory().getLong(ea);
                if (val > 0x140000000L && val < 0x142000000L) {
                    Function f = currentProgram.getFunctionManager().getFunctionAt(
                        currentProgram.getAddressFactory().getAddress(String.format("%x", val)));
                    println(String.format("      vtable[%d] (offset 0x%X) -> 0x%X %s", i, i * 8, val,
                        f != null ? f.getName() + " (size=" + f.getBody().getNumAddresses() + ")" : ""));
                } else {
                    if (i > 2) break; // stop at first non-function-pointer
                }
            }
        } catch (Exception e) {}
    }
}
