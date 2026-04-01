// FindSendtoCallers.java - Find callers of sendto in RiotGamesApi.dll
// sendto is imported by ordinal 18 from WS2_32.dll
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class FindSendtoCallers extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("=== Finding sendto/recvfrom callers ===");

        // Search for all external symbols from WS2_32
        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator symbols = st.getAllSymbols(true);

        List<String> targets = Arrays.asList(
            "sendto", "recvfrom", "send", "recv",
            "WSASendTo", "WSARecvFrom", "WSASend", "WSARecv",
            "Ordinal_18", "Ordinal_19", "Ordinal_20", "Ordinal_21"
        );

        while (symbols.hasNext()) {
            Symbol sym = symbols.next();
            String name = sym.getName();
            boolean isTarget = false;

            for (String t : targets) {
                if (name.equalsIgnoreCase(t) || name.contains(t)) {
                    isTarget = true;
                    break;
                }
            }

            // Also check ordinals 18 (sendto) and 19 (recvfrom)
            if (name.contains("Ordinal") && (name.contains("18") || name.contains("19"))) {
                isTarget = true;
            }

            if (isTarget) {
                println("\n=== " + name + " at " + sym.getAddress() + " ===");

                Reference[] refs = getReferencesTo(sym.getAddress());
                println("  References: " + refs.length);

                Set<String> callers = new HashSet<>();
                for (Reference ref : refs) {
                    Function func = getFunctionContaining(ref.getFromAddress());
                    if (func != null && !callers.contains(func.getName())) {
                        callers.add(func.getName());
                        println("  CALLER: " + func.getName() + " at " + func.getEntryPoint());
                        println("    Call at: " + ref.getFromAddress());

                        // Decompile the caller
                        decompileAndPrint(func, 100);

                        // Find callers of caller (one level up)
                        Reference[] callerRefs = getReferencesTo(func.getEntryPoint());
                        if (callerRefs.length > 0 && callerRefs.length < 20) {
                            println("    Callers of " + func.getName() + ":");
                            for (Reference cr : callerRefs) {
                                Function grandCaller = getFunctionContaining(cr.getFromAddress());
                                if (grandCaller != null) {
                                    println("      " + grandCaller.getName() + " at " + grandCaller.getEntryPoint());
                                }
                            }
                        }
                    }
                }
            }
        }

        println("\n=== DONE ===");
    }

    private void decompileAndPrint(Function func, int maxLines) {
        try {
            ghidra.app.decompiler.DecompInterface decomp = new ghidra.app.decompiler.DecompInterface();
            decomp.openProgram(currentProgram);
            ghidra.app.decompiler.DecompileResults results = decomp.decompileFunction(func, 60, monitor);
            if (results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC();
                String[] lines = code.split("\n");
                println("    --- " + func.getName() + " (" + lines.length + " lines) ---");
                for (int i = 0; i < Math.min(lines.length, maxLines); i++) {
                    println("    " + lines[i]);
                }
                if (lines.length > maxLines) println("    ... (" + (lines.length - maxLines) + " more lines)");
            }
            decomp.dispose();
        } catch (Exception e) {
            println("    Decompile failed: " + e.getMessage());
        }
    }
}
