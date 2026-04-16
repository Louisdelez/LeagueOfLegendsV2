//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.util.*;

/**
 * FindOpcodeTable10 - Direct approach: find the game-level dispatch
 *
 * The consumer (FUN_1405883d0) calls through vtable+0x10 of object at param_1+0x168.
 * FUN_140570d50 starts the consumer. Let's trace the object creation.
 *
 * Also: the consumer iterates batch items and the handler receives:
 *   (handler_obj, &data, &flags, &content, &extra, &channel)
 * The "data" is the raw game packet. The handler must read byte[0] = opcode.
 *
 * Alternative: search the ENTIRE binary for large switch statements on a byte value.
 */
public class FindOpcodeTable10 extends GhidraScript {

    private DecompInterface decomp;

    @Override
    public void run() throws Exception {
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // Phase 1: FUN_140570d50 is a thin wrapper that calls FUN_1405883d0
        println("=== Phase 1: FUN_140570d50 (consumer thread start) ===");
        decompFull(0x140570d50L, 30);

        // Phase 2: Find xrefs to FUN_140570d50 to find who creates the consumer thread
        println("\n=== Phase 2: Who calls FUN_140570d50? ===");
        for (Reference ref : getReferencesTo(toAddr(0x140570d50L))) {
            Function f = getFunctionContaining(ref.getFromAddress());
            if (f != null) {
                println("  From " + ref.getFromAddress() + " in " + f.getName() +
                    "@" + f.getEntryPoint() + " size=" + f.getBody().getNumAddresses());
            } else {
                // Data ref - this might be a thread start address
                println("  Data ref at " + ref.getFromAddress());
                // Read nearby memory to see if it's a thread creation
                try {
                    long addr = ref.getFromAddress().getOffset();
                    for (long a = addr - 0x20; a < addr + 0x20; ) {
                        Address ia = toAddr(a);
                        Instruction inst = currentProgram.getListing().getInstructionAt(ia);
                        if (inst != null) {
                            println("    " + ia + ": " + inst);
                            a += inst.getLength();
                        } else a++;
                    }
                } catch (Exception e) {}
            }
        }

        // Phase 3: The consumer receives param_1 which is the network subsystem object.
        // Let's decompile FUN_14056e640 which we saw initializes vtables
        // It was found in the vtable search earlier
        println("\n=== Phase 3: FUN_14056e640 (vtable initializer) ===");
        decompFull(0x14056e640L, 150);

        // Phase 4: Alternative approach - search for the game packet dispatch
        // In LoL, the game-level handler is called with the raw packet data.
        // The handler reads the first byte (opcode) and dispatches.
        // Let's search for functions that:
        // 1. Are called via vtable+0x10
        // 2. Read the first byte of a buffer argument
        // 3. Have many branches based on that byte

        // The vtable+0x10 handler might be in ANY class. Let's search more broadly.
        // The consumer calls: (**(code **)(*plVar3 + 0x10))(plVar3, data_ptr, ...)
        // So the handler function has signature: void handler(this, data*, flag*, content*, extra*, channel*)

        // Phase 4: Search ALL functions for switch statements with many cases
        // Focus on functions with 15+ cases (game opcodes)
        println("\n=== Phase 4: ALL functions with switch >= 15 cases ===");
        FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
        int checked = 0;
        while (iter.hasNext() && checked < 5000) {
            Function func = iter.next();
            long addr = func.getEntryPoint().getOffset();
            int size = (int) func.getBody().getNumAddresses();

            if (size > 500 && addr > 0x140000000L && addr < 0x141800000L) {
                checked++;
                try {
                    DecompileResults r = decomp.decompileFunction(func, 30, monitor);
                    if (r.decompileCompleted()) {
                        String code = r.getDecompiledFunction().getC();
                        int caseCount = 0;
                        Set<String> caseValues = new TreeSet<>();
                        for (String line : code.split("\n")) {
                            String trimmed = line.trim();
                            if (trimmed.startsWith("case ")) {
                                caseCount++;
                                caseValues.add(trimmed.split(":")[0].trim());
                            }
                        }
                        if (caseCount >= 15) {
                            println(String.format("  %s at 0x%X  size=%d  cases=%d  values=%s",
                                func.getName(), addr, size, caseCount,
                                caseValues.size() > 30 ? caseValues.size() + " unique" : caseValues.toString()));
                        }
                    }
                } catch (Exception e) {}
            }
        }

        // Phase 5: Specifically search for JMP tables (switch compiled as computed goto)
        // in the range 0x140100000 - 0x140570000 (outside the ENet module)
        println("\n=== Phase 5: Jump tables outside ENet range ===");
        findJumpTablesWithContext(0x140100000L, 0x140570000L);

        println("\n=== DONE ===");
        decomp.dispose();
    }

    private void findJumpTablesWithContext(long start, long end) {
        for (long off = start; off < end; ) {
            Address a = toAddr(off);
            Instruction inst = currentProgram.getListing().getInstructionAt(a);
            if (inst != null) {
                String mnem = inst.getMnemonicString();
                if (mnem.equals("JMP") && inst.getNumOperands() > 0) {
                    String op = inst.getDefaultOperandRepresentation(0);
                    // Computed jump: JMP [base + reg*4] or JMP qword ptr [...]
                    if (op.contains("*")) {
                        Function f = getFunctionContaining(a);
                        if (f != null && f.getBody().getNumAddresses() > 200) {
                            // Look back for CMP that gives us the max case
                            int maxCase = findMaxCaseBefore(a, f);
                            if (maxCase >= 10) {
                                println(String.format("  JUMP TABLE at %s: %s  max_case=0x%X  in %s (size=%d)",
                                    a, inst, maxCase, f.getName() + "@" + f.getEntryPoint(),
                                    (int) f.getBody().getNumAddresses()));
                            }
                        }
                    }
                }
                off += inst.getLength();
            } else { off++; }
        }
    }

    private int findMaxCaseBefore(Address jmpAddr, Function func) {
        Address start = jmpAddr.subtract(60);
        if (start.getOffset() < func.getEntryPoint().getOffset())
            start = func.getEntryPoint();

        int maxCase = -1;
        for (Instruction inst : currentProgram.getListing().getInstructions(
                new AddressSet(start, jmpAddr), true)) {
            if (inst.getMnemonicString().equals("CMP") && inst.getNumOperands() >= 2) {
                String op2 = inst.getDefaultOperandRepresentation(1);
                try {
                    op2 = op2.replace("0x", "").trim();
                    try { maxCase = Integer.parseInt(op2, 16); } catch (NumberFormatException e) {
                        try { maxCase = Integer.parseInt(op2); } catch (NumberFormatException e2) {}
                    }
                } catch (Exception e) {}
            }
        }
        return maxCase;
    }

    private void decompFull(long addr, int maxLines) {
        Function f = getFunctionAt(toAddr(addr));
        if (f == null) f = getFunctionContaining(toAddr(addr));
        if (f == null) { println("No function at " + Long.toHexString(addr)); return; }
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
}
