// FindBlowfishXrefs.java - Find all code that references the Blowfish P-box
// The P-box is at offset 0x19ECDC0 in LoLPrivate.exe
// Any code that reads from this address is BF_encrypt, BF_decrypt, or BF_set_key
//
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import java.util.*;

public class FindBlowfishXrefs extends GhidraScript {

    @Override
    public void run() throws Exception {
        // P-box offsets found by our memory scanner
        long[] pboxOffsets = { 0x19ECDC0L, 0x1ADEE20L };

        Address imageBase = currentProgram.getImageBase();
        println("Image base: " + imageBase);

        for (long offset : pboxOffsets) {
            Address pboxAddr = imageBase.add(offset);
            println("\n========================================");
            println("P-BOX at " + pboxAddr + " (offset 0x" + Long.toHexString(offset) + ")");
            println("========================================");

            // Find all references TO this address
            Reference[] refs = getReferencesTo(pboxAddr);
            println("Direct references: " + refs.length);

            for (Reference ref : refs) {
                Address fromAddr = ref.getFromAddress();
                Function func = getFunctionContaining(fromAddr);
                String funcName = func != null ? func.getName() : "<no function>";
                long funcOffset = func != null ? fromAddr.subtract(func.getEntryPoint()) : 0;
                println("  REF from " + fromAddr + " in " + funcName + " (+" + funcOffset + ")");

                if (func != null) {
                    decompileAndPrint(func);
                }
            }

            // Also search for LEA/MOV instructions that load addresses near the P-box
            // The compiler might use base+offset addressing
            println("\nSearching for nearby address references...");
            for (long delta = -0x100; delta <= 0x1100; delta += 0x100) {
                Address searchAddr = pboxAddr.add(delta);
                Reference[] nearRefs = getReferencesTo(searchAddr);
                if (nearRefs.length > 0) {
                    println("  " + nearRefs.length + " refs to " + searchAddr + " (P-box+" + delta + ")");
                    for (Reference ref : nearRefs) {
                        Address fromAddr = ref.getFromAddress();
                        Function func = getFunctionContaining(fromAddr);
                        if (func != null) {
                            println("    from " + fromAddr + " in " + func.getName());
                        }
                    }
                }
            }
        }

        // Also search for the "BF-CBC" string and its references
        println("\n========================================");
        println("Searching for BF-CBC string references");
        println("========================================");

        // Search for "BF-CBC" in memory
        byte[] bfCbcBytes = "BF-CBC".getBytes();
        Address searchStart = currentProgram.getMinAddress();
        Address searchEnd = currentProgram.getMaxAddress();

        Address found = currentProgram.getMemory().findBytes(searchStart, searchEnd, bfCbcBytes, null, true, monitor);
        while (found != null) {
            println("BF-CBC string at " + found);

            // Find references to this string
            Reference[] strRefs = getReferencesTo(found);
            println("  References: " + strRefs.length);
            for (Reference ref : strRefs) {
                Address fromAddr = ref.getFromAddress();
                Function func = getFunctionContaining(fromAddr);
                println("  from " + fromAddr + " in " + (func != null ? func.getName() : "<none>"));
                if (func != null) {
                    decompileAndPrint(func);
                }
            }

            // Search for next occurrence
            found = currentProgram.getMemory().findBytes(found.add(1), searchEnd, bfCbcBytes, null, true, monitor);
        }

        // Search for "EncryptThenMac" string
        println("\n========================================");
        println("Searching for EncryptThenMac string");
        println("========================================");
        byte[] etmBytes = "EncryptThenMac".getBytes();
        found = currentProgram.getMemory().findBytes(searchStart, searchEnd, etmBytes, null, true, monitor);
        while (found != null) {
            println("EncryptThenMac at " + found);
            Reference[] strRefs = getReferencesTo(found);
            for (Reference ref : strRefs) {
                Address fromAddr = ref.getFromAddress();
                Function func = getFunctionContaining(fromAddr);
                println("  from " + fromAddr + " in " + (func != null ? func.getName() : "<none>"));
                if (func != null) {
                    decompileAndPrint(func);
                }
            }
            found = currentProgram.getMemory().findBytes(found.add(1), searchEnd, etmBytes, null, true, monitor);
        }

        println("\n=== DONE ===");
    }

    private void decompileAndPrint(Function func) {
        try {
            ghidra.app.decompiler.DecompInterface decomp = new ghidra.app.decompiler.DecompInterface();
            decomp.openProgram(currentProgram);
            ghidra.app.decompiler.DecompileResults results = decomp.decompileFunction(func, 30, monitor);
            if (results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC();
                // Print first 50 lines
                String[] lines = code.split("\n");
                println("  --- Decompiled " + func.getName() + " (" + lines.length + " lines) ---");
                for (int i = 0; i < Math.min(lines.length, 80); i++) {
                    println("  " + lines[i]);
                }
                if (lines.length > 80) {
                    println("  ... (" + (lines.length - 80) + " more lines)");
                }
                println("  --- End ---");
            }
            decomp.dispose();
        } catch (Exception e) {
            println("  Decompile failed: " + e.getMessage());
        }
    }
}
