//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.util.*;

/**
 * FindOpcodeTable6 - Find the opcode<->packet type mapping
 *
 * S2C_ packet names found in .rdata. These are C++ mangled names for packet structs.
 * The game must map opcode numbers to these packet types somewhere.
 *
 * Strategy:
 * 1. Find xrefs to PKT_ string at 141957628 - this likely contains the packet type registry
 * 2. Search for a table of opcode->handler mappings in .rdata
 * 3. Look for the function that registers packet handlers (creates the mapping)
 * 4. Find all S2C_ strings and their associated opcode values
 */
public class FindOpcodeTable6 extends GhidraScript {

    private DecompInterface decomp;

    @Override
    public void run() throws Exception {
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // Phase 1: Find PKT_ references
        println("=== Phase 1: Xrefs to PKT_ string at 141957628 ===");
        Address pktAddr = toAddr(0x141957628L);
        for (Reference ref : getReferencesTo(pktAddr)) {
            Function f = getFunctionContaining(ref.getFromAddress());
            println("  Ref from " + ref.getFromAddress() +
                (f != null ? " in " + f.getName() + "@" + f.getEntryPoint() +
                " size=" + f.getBody().getNumAddresses() : ""));
        }

        // Phase 2: Find S2C_PlaySoundAtLocation references (at 14195762c)
        println("\n=== Phase 2: Xrefs to S2C_PlaySoundAtLocation ===");
        for (Reference ref : getReferencesTo(toAddr(0x14195762cL))) {
            Function f = getFunctionContaining(ref.getFromAddress());
            println("  Ref from " + ref.getFromAddress() +
                (f != null ? " in " + f.getName() + "@" + f.getEntryPoint() : ""));
        }

        // Phase 3: Broader search - find ALL S2C_ strings and their xrefs
        // Group by the function that references them to find the registration function
        println("\n=== Phase 3: All S2C_ strings and their referencing functions ===");
        Map<String, Integer> funcRefCount = new LinkedHashMap<>();
        List<String[]> allPackets = new ArrayList<>();

        Address searchAddr = currentProgram.getMinAddress();
        while (searchAddr != null) {
            searchAddr = currentProgram.getMemory().findBytes(searchAddr, "S2C_".getBytes(), null, true, monitor);
            if (searchAddr == null) break;

            byte[] buf = new byte[80];
            try {
                currentProgram.getMemory().getBytes(searchAddr, buf);
                String str = new String(buf).split("\0")[0];
                if (str.length() > 4 && str.length() < 75 && !str.contains(" ")) {
                    // Clean up mangled suffix
                    String clean = str;
                    if (clean.contains("@")) clean = clean.split("@")[0];
                    if (clean.endsWith("_s")) clean = clean.substring(0, clean.length() - 2);

                    allPackets.add(new String[]{searchAddr.toString(), clean});

                    for (Reference ref : getReferencesTo(searchAddr)) {
                        Function f = getFunctionContaining(ref.getFromAddress());
                        if (f != null) {
                            String key = f.getEntryPoint().toString();
                            funcRefCount.merge(key, 1, Integer::sum);
                        }
                    }
                }
            } catch (Exception e) {}
            searchAddr = searchAddr.add(1);
        }

        // Also search C2S_ strings
        searchAddr = currentProgram.getMinAddress();
        while (searchAddr != null) {
            searchAddr = currentProgram.getMemory().findBytes(searchAddr, "C2S_".getBytes(), null, true, monitor);
            if (searchAddr == null) break;

            byte[] buf = new byte[80];
            try {
                currentProgram.getMemory().getBytes(searchAddr, buf);
                String str = new String(buf).split("\0")[0];
                if (str.length() > 4 && str.length() < 75 && !str.contains(" ")) {
                    String clean = str;
                    if (clean.contains("@")) clean = clean.split("@")[0];
                    if (clean.endsWith("_s")) clean = clean.substring(0, clean.length() - 2);

                    allPackets.add(new String[]{searchAddr.toString(), clean});

                    for (Reference ref : getReferencesTo(searchAddr)) {
                        Function f = getFunctionContaining(ref.getFromAddress());
                        if (f != null) {
                            String key = f.getEntryPoint().toString();
                            funcRefCount.merge(key, 1, Integer::sum);
                        }
                    }
                }
            } catch (Exception e) {}
            searchAddr = searchAddr.add(1);
        }

        println("Total S2C_/C2S_ packet strings found: " + allPackets.size());
        for (String[] p : allPackets) {
            println("  " + p[0] + ": " + p[1]);
        }

        // Phase 4: Find the function(s) that reference the most packet strings
        // This is likely the packet registration function
        println("\n=== Phase 4: Functions referencing most packet strings ===");
        List<Map.Entry<String, Integer>> sorted = new ArrayList<>(funcRefCount.entrySet());
        sorted.sort((a, b) -> b.getValue() - a.getValue());
        for (int i = 0; i < Math.min(10, sorted.size()); i++) {
            Map.Entry<String, Integer> e = sorted.get(i);
            Function f = getFunctionAt(toAddr(e.getKey()));
            println(String.format("  %s at %s  size=%d  packet_refs=%d",
                f != null ? f.getName() : "?", e.getKey(),
                f != null ? (int) f.getBody().getNumAddresses() : 0, e.getValue()));
        }

        // Phase 5: Decompile the top candidate (packet registration function)
        if (!sorted.isEmpty()) {
            String topFunc = sorted.get(0).getKey();
            println("\n=== Phase 5: Decompile top packet registration function at " + topFunc + " ===");
            Function f = getFunctionAt(toAddr(topFunc));
            if (f != null) {
                DecompileResults r = decomp.decompileFunction(f, 600, monitor);
                if (r.decompileCompleted()) {
                    String code = r.getDecompiledFunction().getC();
                    String[] lines = code.split("\n");
                    println("Total lines: " + lines.length);
                    // Print lines that contain opcode-like values or packet names
                    for (int i = 0; i < lines.length; i++) {
                        String line = lines[i].trim();
                        if (line.contains("0x") || line.contains("S2C_") || line.contains("C2S_") ||
                            line.contains("PKT_") || line.contains("case ") || line.contains("switch") ||
                            line.contains("handler") || line.contains("register") ||
                            i < 30 || (i % 20 == 0)) {
                            println(String.format("  [%d] %s", i, lines[i]));
                        }
                    }
                }
            }
        }

        // Phase 6: Look for a different pattern - opcode constants near S2C_ string refs
        // The registration might look like: register(0x42, "S2C_Something", handler)
        // Search for the function that has both a numeric constant AND a string ref nearby
        println("\n=== Phase 6: Looking for opcode values near S2C_ string references ===");
        if (!sorted.isEmpty()) {
            Function topF = getFunctionAt(toAddr(sorted.get(0).getKey()));
            if (topF != null) {
                // Scan the function for MOV with immediate values followed by references to S2C_ strings
                Address lastStringRef = null;
                String lastString = "";
                Map<Integer, String> opcodeMap = new TreeMap<>();

                for (Instruction inst : currentProgram.getListing().getInstructions(topF.getBody(), true)) {
                    // Check if this instruction references an S2C_/C2S_ string
                    for (Reference ref : inst.getReferencesFrom()) {
                        Address target = ref.getToAddress();
                        try {
                            byte[] b = new byte[4];
                            currentProgram.getMemory().getBytes(target, b);
                            String s = new String(b);
                            if (s.startsWith("S2C_") || s.startsWith("C2S_") || s.startsWith("PKT_")) {
                                byte[] full = new byte[64];
                                currentProgram.getMemory().getBytes(target, full);
                                lastString = new String(full).split("\0")[0];
                                if (lastString.contains("@")) lastString = lastString.split("@")[0];
                                lastStringRef = inst.getAddress();
                            }
                        } catch (Exception e) {}
                    }

                    // Check for MOV with immediate value (potential opcode)
                    if (inst.getMnemonicString().equals("MOV") && inst.getNumOperands() >= 2) {
                        String op2 = inst.getDefaultOperandRepresentation(1);
                        try {
                            String val = op2.replace("0x", "").trim();
                            int v = Integer.parseInt(val, 16);
                            if (v > 0 && v < 0x200 && lastStringRef != null) {
                                long dist = Math.abs(inst.getAddress().getOffset() - lastStringRef.getOffset());
                                if (dist < 100) {
                                    opcodeMap.put(v, lastString);
                                }
                            }
                        } catch (Exception e) {}
                    }
                }

                println("Potential opcode -> packet name mappings:");
                for (Map.Entry<Integer, String> e : opcodeMap.entrySet()) {
                    println(String.format("  opcode 0x%04X (%d) -> %s", e.getKey(), e.getKey(), e.getValue()));
                }
            }
        }

        println("\n=== DONE ===");
        decomp.dispose();
    }
}
