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
 * FindOpcodeTable - Finds the game packet opcode dispatch table in LoL 16.6
 *
 * Strategy:
 * 1. Start from FUN_14057dce0 (handler after CRC) and walk callees
 * 2. Look for functions with large switch statements (many CMP/JZ or jump tables)
 * 3. Identify opcode byte reads (MOVZX from buffer) followed by dispatch
 * 4. Extract the opcode->handler mapping
 */
public class FindOpcodeTable extends GhidraScript {

    private DecompInterface decomp;
    private Address imageBase;

    @Override
    public void run() throws Exception {
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        imageBase = currentProgram.getImageBase();

        println("=== FindOpcodeTable: Searching for game packet opcode dispatch ===");

        // Phase 1: Walk callees of FUN_14057dce0 to find the dispatch function
        println("\n--- Phase 1: Callees of FUN_14057dce0 (handler entry) ---");
        Address entryAddr = addr("14057dce0");
        Function entryFunc = getFuncAt(entryAddr);
        if (entryFunc != null) {
            List<Function> callees = getCallees(entryFunc);
            println("FUN_14057dce0 calls " + callees.size() + " functions:");
            for (Function callee : callees) {
                int switchCount = countSwitchPatterns(callee);
                int size = (int) callee.getBody().getNumAddresses();
                println(String.format("  %s at %s  size=%d  switch_indicators=%d",
                    callee.getName(), callee.getEntryPoint(), size, switchCount));
            }

            // Decompile the entry function itself to see how it reads the opcode
            println("\n--- Decompile FUN_14057dce0 (first 80 lines) ---");
            decompileAndPrint(entryFunc, 80);
        }

        // Phase 2: Search for large switch/jump table patterns in the packet processing range
        println("\n--- Phase 2: Scanning for jump tables (0x14057d000 - 0x14058f000) ---");
        findJumpTables(0x14057d000L, 0x14058f000L);

        // Phase 3: Look for MOVZX + CMP chains (opcode byte read + comparison)
        println("\n--- Phase 3: Looking for opcode CMP chains ---");
        findOpcodeCmpChains(0x14057d000L, 0x14058f000L);

        // Phase 4: Check specific functions that might be the dispatcher
        // Walk deeper: callees of callees of FUN_14057dce0
        println("\n--- Phase 4: Deep callee analysis (2 levels from entry) ---");
        if (entryFunc != null) {
            Set<String> seen = new HashSet<>();
            for (Function callee : getCallees(entryFunc)) {
                for (Function callee2 : getCallees(callee)) {
                    String key = callee2.getEntryPoint().toString();
                    if (seen.add(key)) {
                        int switchCount = countSwitchPatterns(callee2);
                        int size = (int) callee2.getBody().getNumAddresses();
                        if (switchCount >= 3 || size > 2000) {
                            println(String.format("  CANDIDATE: %s at %s  size=%d  switch_indicators=%d",
                                callee2.getName(), callee2.getEntryPoint(), size, switchCount));
                            // Decompile candidates with many switch indicators
                            if (switchCount >= 5) {
                                println("    --- Decompile (first 120 lines) ---");
                                decompileAndPrint(callee2, 120);
                            }
                        }
                    }
                }
            }
        }

        // Phase 5: Search for the classic ENet/LoL opcode pattern:
        // Read first byte from data buffer, use as switch index
        // Also look for known opcodes: KeyCheck uses specific values
        println("\n--- Phase 5: Searching for known opcode constants ---");
        // KeyCheck packet is typically identified by specific size (148 bytes) or opcode
        // Search for CMP with common LoL opcodes in the network range
        int[] knownOpcodes = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
                              0x24, 0x34, 0x64, 0x65, 0xFE, 0xFF};
        findSpecificOpcodeComparisons(0x14057d000L, 0x14058f000L, knownOpcodes);

        // Phase 6: Look for functions that read a single byte then branch many ways
        println("\n--- Phase 6: Functions with MOVZX from memory + large branch count ---");
        findMovzxDispatch(0x14057c000L, 0x140590000L);

        println("\n=== FindOpcodeTable DONE ===");
        decomp.dispose();
    }

    private Address addr(String hex) {
        return currentProgram.getAddressFactory().getAddress(hex);
    }

    private Function getFuncAt(Address a) {
        Function f = currentProgram.getFunctionManager().getFunctionAt(a);
        if (f == null) f = currentProgram.getFunctionManager().getFunctionContaining(a);
        return f;
    }

    private List<Function> getCallees(Function func) {
        Set<Address> seen = new LinkedHashSet<>();
        List<Function> result = new ArrayList<>();
        for (Instruction inst : currentProgram.getListing().getInstructions(func.getBody(), true)) {
            if (inst.getMnemonicString().equals("CALL")) {
                for (Reference ref : inst.getReferencesFrom()) {
                    Address target = ref.getToAddress();
                    if (seen.add(target)) {
                        Function callee = currentProgram.getFunctionManager().getFunctionAt(target);
                        if (callee != null) result.add(callee);
                    }
                }
            }
        }
        return result;
    }

    private int countSwitchPatterns(Function func) {
        int count = 0;
        int cmpCount = 0;
        boolean hasJumpTable = false;

        for (Instruction inst : currentProgram.getListing().getInstructions(func.getBody(), true)) {
            String mnem = inst.getMnemonicString();
            // Count CMP instructions (switch cases)
            if (mnem.equals("CMP")) cmpCount++;
            // Look for JMP with computed target (jump table)
            if (mnem.equals("JMP") && inst.getNumOperands() > 0) {
                String op = inst.getDefaultOperandRepresentation(0);
                if (op.contains("[") && (op.contains("*") || op.contains("+"))) {
                    hasJumpTable = true;
                    count += 10; // Strong indicator
                }
            }
        }
        count += cmpCount;
        return count;
    }

    private void findJumpTables(long startOff, long endOff) {
        // Look for JMP qword ptr [REG*8 + addr] patterns (computed jump tables)
        for (long off = startOff; off < endOff; ) {
            Address a = addr(String.format("%x", off));
            Instruction inst = currentProgram.getListing().getInstructionAt(a);
            if (inst != null) {
                String mnem = inst.getMnemonicString();
                if (mnem.equals("JMP") && inst.getNumOperands() > 0) {
                    String op = inst.getDefaultOperandRepresentation(0);
                    if (op.contains("*")) {
                        Function f = currentProgram.getFunctionManager().getFunctionContaining(a);
                        println(String.format("  JUMP TABLE at %s: %s  (in %s)",
                            a, inst, f != null ? f.getName() + " @ " + f.getEntryPoint() : "unknown"));

                        // Try to extract table entries
                        extractJumpTable(inst, a);
                    }
                }
                off += inst.getLength();
            } else {
                off++;
            }
        }
    }

    private void extractJumpTable(Instruction jmpInst, Address jmpAddr) {
        // Look for the switch variable setup before this JMP
        // Typically: CMP reg, N; JA default; ... JMP [reg*8+table]
        // Search backwards for the CMP that sets the upper bound
        Function func = currentProgram.getFunctionManager().getFunctionContaining(jmpAddr);
        if (func == null) return;

        // Find the JA/JAE before the JMP that tells us the case count
        Address searchStart = jmpAddr.subtract(50);
        if (searchStart.getOffset() < func.getEntryPoint().getOffset())
            searchStart = func.getEntryPoint();

        int maxCase = -1;
        for (Instruction inst : currentProgram.getListing().getInstructions(
                new AddressSet(searchStart, jmpAddr), true)) {
            String mnem = inst.getMnemonicString();
            if (mnem.equals("CMP")) {
                // Try to get the immediate operand (max case value)
                try {
                    if (inst.getNumOperands() >= 2) {
                        String op2 = inst.getDefaultOperandRepresentation(1);
                        // Remove 0x prefix if present
                        op2 = op2.replace("0x", "").trim();
                        try {
                            maxCase = Integer.parseInt(op2, 16);
                        } catch (NumberFormatException e) {
                            try { maxCase = Integer.parseInt(op2); } catch (NumberFormatException e2) {}
                        }
                    }
                } catch (Exception e) {}
            }
        }

        if (maxCase > 0) {
            println(String.format("    Max case value: 0x%X (%d cases)", maxCase, maxCase + 1));
        }

        // Try to read the jump table address from the instruction
        // The table base address is embedded in the JMP instruction
        String fullInst = jmpInst.toString();
        // Try to extract addresses from references
        for (Reference ref : jmpInst.getReferencesFrom()) {
            if (ref.getReferenceType().isData()) {
                Address tableAddr = ref.getToAddress();
                println("    Table base: " + tableAddr);
                // Read table entries (each is 8 bytes for x64)
                int numEntries = maxCase > 0 ? Math.min(maxCase + 1, 256) : 16;
                try {
                    for (int i = 0; i < numEntries; i++) {
                        long entry = currentProgram.getMemory().getLong(tableAddr.add(i * 8));
                        if (entry > 0x140000000L && entry < 0x142000000L) {
                            Function handler = currentProgram.getFunctionManager().getFunctionAt(
                                addr(String.format("%x", entry)));
                            println(String.format("    case 0x%02X -> 0x%X %s", i, entry,
                                handler != null ? "(" + handler.getName() + ")" : ""));
                        } else {
                            // Might be relative offsets (32-bit)
                            break;
                        }
                    }
                    // Also try 4-byte relative offsets
                    boolean tried4byte = false;
                    for (int i = 0; i < numEntries && !tried4byte; i++) {
                        int relOffset = currentProgram.getMemory().getInt(tableAddr.add(i * 4));
                        long absAddr = tableAddr.getOffset() + relOffset;
                        if (absAddr > 0x140000000L && absAddr < 0x142000000L) {
                            if (i == 0) println("    (Trying 4-byte relative offsets from table base)");
                            tried4byte = true;
                            for (int j = 0; j < numEntries; j++) {
                                int rel = currentProgram.getMemory().getInt(tableAddr.add(j * 4));
                                long abs = tableAddr.getOffset() + rel;
                                if (abs > 0x140000000L && abs < 0x142000000L) {
                                    Function h = currentProgram.getFunctionManager().getFunctionAt(
                                        addr(String.format("%x", abs)));
                                    println(String.format("    case 0x%02X -> 0x%X %s", j, abs,
                                        h != null ? "(" + h.getName() + ")" : ""));
                                } else {
                                    println(String.format("    case 0x%02X -> (invalid: 0x%X)", j, abs));
                                    if (j > 3) break; // stop if too many invalid
                                }
                            }
                        }
                    }
                } catch (MemoryAccessException e) {
                    println("    (Cannot read table: " + e.getMessage() + ")");
                }
            }
        }
    }

    private void findOpcodeCmpChains(long startOff, long endOff) {
        // Look for sequences of CMP reg, imm8; JZ/JE target (opcode comparison chains)
        // These indicate if-else opcode dispatch
        Map<Long, List<Integer>> funcCmpValues = new LinkedHashMap<>();

        for (long off = startOff; off < endOff; ) {
            Address a = addr(String.format("%x", off));
            Instruction inst = currentProgram.getListing().getInstructionAt(a);
            if (inst != null) {
                if (inst.getMnemonicString().equals("CMP") && inst.getNumOperands() >= 2) {
                    String op1 = inst.getDefaultOperandRepresentation(0);
                    String op2 = inst.getDefaultOperandRepresentation(1);
                    // Check if comparing a byte register with an immediate
                    if ((op1.contains("L") || op1.contains("l") || op1.equals("AL") ||
                         op1.equals("CL") || op1.equals("DL") || op1.equals("BL") ||
                         op1.equals("R8B") || op1.equals("R9B") || op1.equals("R10B") || op1.equals("R11B") ||
                         op1.equals("DIL") || op1.equals("SIL")) && !op2.contains("[")) {
                        Function func = currentProgram.getFunctionManager().getFunctionContaining(a);
                        if (func != null) {
                            long funcAddr = func.getEntryPoint().getOffset();
                            if (!funcCmpValues.containsKey(funcAddr))
                                funcCmpValues.put(funcAddr, new ArrayList<>());
                            try {
                                String val = op2.replace("0x", "").trim();
                                int v = Integer.parseInt(val, 16);
                                funcCmpValues.get(funcAddr).add(v);
                            } catch (NumberFormatException e) {
                                try {
                                    funcCmpValues.get(funcAddr).add(Integer.parseInt(op2.trim()));
                                } catch (NumberFormatException e2) {}
                            }
                        }
                    }
                }
                off += inst.getLength();
            } else {
                off++;
            }
        }

        // Print functions with many byte comparisons (likely opcode dispatchers)
        for (Map.Entry<Long, List<Integer>> entry : funcCmpValues.entrySet()) {
            if (entry.getValue().size() >= 4) {
                Function f = currentProgram.getFunctionManager().getFunctionAt(
                    addr(String.format("%x", entry.getKey())));
                String name = f != null ? f.getName() : "unknown";
                int size = f != null ? (int) f.getBody().getNumAddresses() : 0;
                List<Integer> vals = entry.getValue();
                StringBuilder sb = new StringBuilder();
                for (int v : vals) sb.append(String.format("0x%02X ", v));
                println(String.format("  %s at 0x%X  size=%d  byte_cmps=%d  values=[%s]",
                    name, entry.getKey(), size, vals.size(), sb.toString().trim()));
            }
        }
    }

    private void findSpecificOpcodeComparisons(long startOff, long endOff, int[] opcodes) {
        // For each known opcode, search for CMP instructions with that value
        // Focus on byte-sized comparisons
        for (long off = startOff; off < endOff; ) {
            Address a = addr(String.format("%x", off));
            Instruction inst = currentProgram.getListing().getInstructionAt(a);
            if (inst != null) {
                if (inst.getMnemonicString().equals("CMP") && inst.getNumOperands() >= 2) {
                    String op2 = inst.getDefaultOperandRepresentation(1);
                    try {
                        String val = op2.replace("0x", "").trim();
                        int v = -1;
                        try { v = Integer.parseInt(val, 16); } catch (Exception e) {
                            try { v = Integer.parseInt(val); } catch (Exception e2) {}
                        }
                        // Check if it matches a known opcode and is in interesting range
                        if (v >= 0) {
                            for (int opc : opcodes) {
                                if (v == opc) {
                                    Function func = currentProgram.getFunctionManager().getFunctionContaining(a);
                                    // Only print if function is large enough to be a dispatcher
                                    if (func != null && func.getBody().getNumAddresses() > 500) {
                                        println(String.format("  CMP with 0x%02X at %s in %s (size=%d)",
                                            v, a, func.getName() + "@" + func.getEntryPoint(),
                                            func.getBody().getNumAddresses()));
                                    }
                                    break;
                                }
                            }
                        }
                    } catch (Exception e) {}
                }
                off += inst.getLength();
            } else {
                off++;
            }
        }
    }

    private void findMovzxDispatch(long startOff, long endOff) {
        // Find MOVZX patterns that read a byte from a buffer pointer
        // followed by switch-like dispatch
        Map<Long, Integer> funcMovzxCount = new LinkedHashMap<>();

        for (long off = startOff; off < endOff; ) {
            Address a = addr(String.format("%x", off));
            Instruction inst = currentProgram.getListing().getInstructionAt(a);
            if (inst != null) {
                String mnem = inst.getMnemonicString();
                if (mnem.equals("MOVZX") && inst.getNumOperands() >= 2) {
                    String op2 = inst.getDefaultOperandRepresentation(1);
                    // MOVZX reg, byte ptr [reg+offset] - reading from buffer
                    if (op2.contains("byte ptr") || op2.contains("BYTE PTR") ||
                        (op2.contains("[") && !op2.contains("*"))) {
                        Function func = currentProgram.getFunctionManager().getFunctionContaining(a);
                        if (func != null) {
                            long fAddr = func.getEntryPoint().getOffset();
                            funcMovzxCount.merge(fAddr, 1, Integer::sum);
                        }
                    }
                }
                off += inst.getLength();
            } else {
                off++;
            }
        }

        // Functions with many MOVZX from memory = packet parsers
        List<Map.Entry<Long, Integer>> sorted = new ArrayList<>(funcMovzxCount.entrySet());
        sorted.sort((a1, b) -> b.getValue() - a1.getValue());

        println("  Top functions by MOVZX-from-memory count:");
        int shown = 0;
        for (Map.Entry<Long, Integer> entry : sorted) {
            if (shown >= 15) break;
            Function f = currentProgram.getFunctionManager().getFunctionAt(
                addr(String.format("%x", entry.getKey())));
            if (f != null && f.getBody().getNumAddresses() > 200) {
                println(String.format("    %s at 0x%X  size=%d  movzx_count=%d",
                    f.getName(), entry.getKey(), (int) f.getBody().getNumAddresses(), entry.getValue()));
                shown++;
            }
        }

        // Phase 6b: For top candidates, decompile and look for switch on first byte
        println("\n--- Phase 6b: Decompiling top MOVZX candidates ---");
        shown = 0;
        for (Map.Entry<Long, Integer> entry : sorted) {
            if (shown >= 5) break;
            Function f = currentProgram.getFunctionManager().getFunctionAt(
                addr(String.format("%x", entry.getKey())));
            if (f != null && f.getBody().getNumAddresses() > 500 && entry.getValue() >= 5) {
                DecompileResults r = decomp.decompileFunction(f, 120, monitor);
                if (r.decompileCompleted()) {
                    String code = r.getDecompiledFunction().getC();
                    // Check for switch statement
                    if (code.contains("switch") || code.contains("case 0x") || code.contains("case 0")) {
                        println(String.format("  *** SWITCH FOUND in %s at 0x%X ***",
                            f.getName(), entry.getKey()));
                        // Print the switch and case lines
                        for (String line : code.split("\n")) {
                            String trimmed = line.trim();
                            if (trimmed.startsWith("switch") || trimmed.startsWith("case ") ||
                                trimmed.startsWith("default:") || trimmed.contains("switch (")) {
                                println("    " + trimmed);
                            }
                        }
                        println("    --- Full decompilation (first 150 lines) ---");
                        String[] lines = code.split("\n");
                        for (int i = 0; i < Math.min(150, lines.length); i++)
                            println("    " + lines[i]);
                        shown++;
                    }
                }
            }
        }
    }

    private void decompileAndPrint(Function func, int maxLines) {
        try {
            DecompileResults r = decomp.decompileFunction(func, 300, monitor);
            if (r.decompileCompleted()) {
                String[] lines = r.getDecompiledFunction().getC().split("\n");
                for (int i = 0; i < Math.min(maxLines, lines.length); i++)
                    println("  " + lines[i]);
                if (lines.length > maxLines)
                    println("  ... (" + (lines.length - maxLines) + " more lines)");
            } else {
                println("  Decompile failed: " + r.getErrorMessage());
            }
        } catch (Exception e) {
            println("  Error: " + e.getMessage());
        }
    }
}
