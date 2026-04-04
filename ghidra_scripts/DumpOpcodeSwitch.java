//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.util.*;

/**
 * DumpOpcodeSwitch - Decompile the candidate opcode dispatchers and extract mappings
 */
public class DumpOpcodeSwitch extends GhidraScript {

    private DecompInterface decomp;

    @Override
    public void run() throws Exception {
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // Primary target: FUN_140955c20 (81 cases, 5284 bytes)
        println("=== FUN_140955c20 (81 cases, 5284 bytes) - PRIME CANDIDATE ===");
        dumpSwitchFunction(0x140955c20L);

        // Secondary: FUN_14034a770 (35 cases)
        println("\n=== FUN_14034a770 (35 cases, 722 bytes) ===");
        dumpSwitchFunction(0x14034a770L);

        // Tertiary: FUN_140341c70 (34 cases)
        println("\n=== FUN_140341c70 (34 cases, 1349 bytes) ===");
        dumpSwitchFunction(0x140341c70L);

        // Also: FUN_140518c90 (22 cases with high opcode values 0x39, 0x77, etc.)
        println("\n=== FUN_140518c90 (22 cases with high opcodes) ===");
        dumpSwitchFunction(0x140518c90L);

        println("\n=== DONE ===");
        decomp.dispose();
    }

    private void dumpSwitchFunction(long addr) {
        Function f = getFunctionAt(toAddr(addr));
        if (f == null) { println("No function at " + Long.toHexString(addr)); return; }
        println("Function: " + f.getName() + " at " + f.getEntryPoint() +
            " size=" + f.getBody().getNumAddresses());

        try {
            DecompileResults r = decomp.decompileFunction(f, 600, monitor);
            if (!r.decompileCompleted()) { println("Decompile failed"); return; }

            String code = r.getDecompiledFunction().getC();
            String[] lines = code.split("\n");
            println("Total lines: " + lines.length);

            // Extract switch variable and all case values with their handler calls
            boolean inSwitch = false;
            String currentCase = "";
            List<String> switchLines = new ArrayList<>();

            for (int i = 0; i < lines.length; i++) {
                String trimmed = lines[i].trim();

                // Print function signature
                if (i < 5) {
                    println("  " + lines[i]);
                    continue;
                }

                // Capture switch statements and cases
                if (trimmed.contains("switch")) {
                    println("  [" + i + "] " + trimmed);
                    inSwitch = true;
                }
                if (trimmed.startsWith("case ")) {
                    currentCase = trimmed.split(":")[0].trim();
                    println("  [" + i + "] " + trimmed);
                    // Print next few lines to see what each case does
                    for (int j = i + 1; j < Math.min(i + 5, lines.length); j++) {
                        String next = lines[j].trim();
                        if (next.startsWith("case ") || next.startsWith("default:") || next.equals("break;")) break;
                        if (next.contains("FUN_") || next.contains("return") || next.contains("goto") ||
                            next.contains("param_") || next.contains("0x")) {
                            println("    " + next);
                        }
                    }
                }
                if (trimmed.startsWith("default:")) {
                    println("  [" + i + "] " + trimmed);
                }
            }

            // Also print callers of this function
            println("\n  Callers:");
            for (Reference ref : getReferencesTo(f.getEntryPoint())) {
                Function caller = getFunctionContaining(ref.getFromAddress());
                if (caller != null) {
                    println("    " + caller.getName() + "@" + caller.getEntryPoint() +
                        " size=" + caller.getBody().getNumAddresses());
                }
            }

            // Print callees
            println("  Callees:");
            Set<String> seen = new HashSet<>();
            for (Instruction inst : currentProgram.getListing().getInstructions(f.getBody(), true)) {
                if (inst.getMnemonicString().equals("CALL")) {
                    for (Reference ref : inst.getReferencesFrom()) {
                        Function target = getFunctionAt(ref.getToAddress());
                        if (target != null && seen.add(target.getEntryPoint().toString())) {
                            println("    -> " + target.getName() + "@" + target.getEntryPoint() +
                                " size=" + target.getBody().getNumAddresses());
                        }
                    }
                }
            }
        } catch (Exception e) { println("Error: " + e.getMessage()); }
    }
}
