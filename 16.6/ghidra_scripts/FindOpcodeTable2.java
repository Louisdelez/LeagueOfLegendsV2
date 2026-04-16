//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.util.*;

/**
 * FindOpcodeTable2 - More targeted search for game opcode dispatch
 *
 * The ENet layer (FUN_14057e910) switches on command type (1-8 = ENet protocol commands).
 * The GAME opcode is inside the data payload, read AFTER ENet delivers it.
 *
 * Strategy:
 * 1. Decompile FUN_14057e910 fully - it dispatches ENet commands, case 8 = "data" channel
 * 2. Follow the "data" path to find where the game reads the first byte
 * 3. Widen search for switch/jump tables to the full binary range
 * 4. Look for functions that read byte[0] from a buffer then dispatch via function pointer table
 */
public class FindOpcodeTable2 extends GhidraScript {

    private DecompInterface decomp;

    @Override
    public void run() throws Exception {
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // Phase 1: Decompile FUN_14057e910 - the ENet command switch
        println("=== Phase 1: ENet command dispatcher FUN_14057e910 ===");
        decompFull("14057e910", 200);

        // Phase 2: Decompile FUN_14057dd10 - high MOVZX count, near the handler entry
        println("\n=== Phase 2: FUN_14057dd10 (near handler entry, 11 movzx) ===");
        decompFull("14057dd10", 100);

        // Phase 3: Decompile FUN_14057dec0 - also near handler, 8 movzx
        println("\n=== Phase 3: FUN_14057dec0 (near handler, 8 movzx) ===");
        decompFull("14057dec0", 100);

        // Phase 4: Check FUN_140588f70 - the big recv handler that calls vtable dispatch
        // We know this function processes received data after CRC
        println("\n=== Phase 4: FUN_140588f70 (recv handler, vtable dispatch) ===");
        Function f88f70 = getFuncAt("140588f70");
        if (f88f70 != null) {
            // List all callees
            println("Callees of FUN_140588f70:");
            for (Instruction inst : currentProgram.getListing().getInstructions(f88f70.getBody(), true)) {
                if (inst.getMnemonicString().equals("CALL")) {
                    for (Reference ref : inst.getReferencesFrom()) {
                        Function target = currentProgram.getFunctionManager().getFunctionAt(ref.getToAddress());
                        if (target != null) {
                            println("  -> " + target.getName() + " at " + target.getEntryPoint() +
                                    " size=" + target.getBody().getNumAddresses());
                        }
                    }
                }
            }
        }

        // Phase 5: Search broader range for jump tables (computed jumps)
        println("\n=== Phase 5: Jump tables in broader range (0x14056e000 - 0x1405a0000) ===");
        findJumpTables(0x14056e000L, 0x1405a0000L);

        // Phase 6: The game opcode dispatch might use a map/table lookup
        // Search for patterns like: handler_table[opcode](...)
        // In C++ this often looks like: std::map or std::unordered_map lookup
        // Or: function_pointer_array[byte_value](args)
        // Search for LEA with a base address + register*8 (function pointer table)
        println("\n=== Phase 6: Function pointer table patterns (MOV RAX, [base + REG*8]) ===");
        findFuncPtrTables(0x14056e000L, 0x1405a0000L);

        // Phase 7: Look for the actual game packet consumer
        // After ENet delivers data via command type 8 (unreliable) or 6 (reliable),
        // the game reassembles and then reads opcode byte
        // Check xrefs FROM FUN_14057e910's callees
        println("\n=== Phase 7: Callees of FUN_14057e910 (ENet command dispatcher) ===");
        Function fE910 = getFuncAt("14057e910");
        if (fE910 != null) {
            Set<String> seen = new HashSet<>();
            for (Instruction inst : currentProgram.getListing().getInstructions(fE910.getBody(), true)) {
                if (inst.getMnemonicString().equals("CALL")) {
                    for (Reference ref : inst.getReferencesFrom()) {
                        Function target = currentProgram.getFunctionManager().getFunctionAt(ref.getToAddress());
                        if (target != null && seen.add(target.getEntryPoint().toString())) {
                            int size = (int) target.getBody().getNumAddresses();
                            println("  " + target.getName() + " at " + target.getEntryPoint() + " size=" + size);
                        }
                    }
                }
            }
        }

        // Phase 8: Decompile key functions around the data delivery path
        // FUN_1405853c0 has CMP with 0xFF, 0x01, 0x02, 0x04 - looks like it parses packet fields
        println("\n=== Phase 8: FUN_1405853c0 (CMP 0xFF, 0x01, 0x02 - possible opcode parse) ===");
        decompFull("1405853c0", 120);

        // Phase 9: FUN_14057d260 has CMP 0x01, 0x02, 0x04, 0x00 - right in the handler area
        println("\n=== Phase 9: FUN_14057d260 (CMP 0x01, 0x02, 0x04, 0x00 - handler area) ===");
        decompFull("14057d260", 120);

        // Phase 10: Search wider for switch statements (anywhere in .text)
        // Game opcode handler might be outside the 0x1405xxxxx range
        println("\n=== Phase 10: Searching for large switch statements (case count >= 10) ===");
        findLargeSwitchStatements();

        println("\n=== FindOpcodeTable2 DONE ===");
        decomp.dispose();
    }

    private Function getFuncAt(String hexAddr) {
        Address a = currentProgram.getAddressFactory().getAddress(hexAddr);
        Function f = currentProgram.getFunctionManager().getFunctionAt(a);
        if (f == null) f = currentProgram.getFunctionManager().getFunctionContaining(a);
        return f;
    }

    private void decompFull(String hexAddr, int maxLines) {
        Function f = getFuncAt(hexAddr);
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

    private void findJumpTables(long start, long end) {
        for (long off = start; off < end; ) {
            Address a = currentProgram.getAddressFactory().getAddress(String.format("%x", off));
            Instruction inst = currentProgram.getListing().getInstructionAt(a);
            if (inst != null) {
                String mnem = inst.getMnemonicString();
                if (mnem.equals("JMP") && inst.getNumOperands() > 0) {
                    String op = inst.getDefaultOperandRepresentation(0);
                    if (op.contains("*") || (op.contains("[") && op.contains("+"))) {
                        Function f = currentProgram.getFunctionManager().getFunctionContaining(a);
                        println(String.format("  JUMP TABLE at %s: %s  in %s",
                            a, inst, f != null ? f.getName() + "@" + f.getEntryPoint() : "?"));
                    }
                }
                off += inst.getLength();
            } else { off++; }
        }
    }

    private void findFuncPtrTables(long start, long end) {
        for (long off = start; off < end; ) {
            Address a = currentProgram.getAddressFactory().getAddress(String.format("%x", off));
            Instruction inst = currentProgram.getListing().getInstructionAt(a);
            if (inst != null) {
                String mnem = inst.getMnemonicString();
                // Look for CALL [reg + reg*8 + base] or MOV reg, [base + reg*8]
                if ((mnem.equals("CALL") || mnem.equals("MOV") || mnem.equals("LEA")) && inst.getNumOperands() > 0) {
                    for (int i = 0; i < inst.getNumOperands(); i++) {
                        String op = inst.getDefaultOperandRepresentation(i);
                        if (op.contains("*0x8") || op.contains("*8")) {
                            Function f = currentProgram.getFunctionManager().getFunctionContaining(a);
                            println(String.format("  PTR TABLE at %s: %s  in %s",
                                a, inst, f != null ? f.getName() + "@" + f.getEntryPoint() : "?"));
                        }
                    }
                }
                off += inst.getLength();
            } else { off++; }
        }
    }

    private void findLargeSwitchStatements() {
        // Iterate over all functions, decompile those that are large and in the network range
        // Look for switch statements with many cases
        FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
        int checked = 0;
        while (iter.hasNext() && checked < 2000) {
            Function f = iter.next();
            long addr = f.getEntryPoint().getOffset();
            int size = (int) f.getBody().getNumAddresses();

            // Focus on large functions in the likely game protocol range
            if (size > 1500 && addr > 0x140100000L && addr < 0x141000000L) {
                checked++;
                try {
                    DecompileResults r = decomp.decompileFunction(f, 60, monitor);
                    if (r.decompileCompleted()) {
                        String code = r.getDecompiledFunction().getC();
                        // Count case statements
                        int caseCount = 0;
                        Set<String> caseValues = new TreeSet<>();
                        for (String line : code.split("\n")) {
                            String trimmed = line.trim();
                            if (trimmed.startsWith("case ")) {
                                caseCount++;
                                caseValues.add(trimmed.split(":")[0].trim());
                            }
                        }
                        if (caseCount >= 10) {
                            println(String.format("  %s at 0x%X  size=%d  cases=%d  values=%s",
                                f.getName(), addr, size, caseCount,
                                caseValues.size() > 20 ? caseValues.size() + " unique" : caseValues.toString()));
                        }
                    }
                } catch (Exception e) {}
            }
        }
    }
}
