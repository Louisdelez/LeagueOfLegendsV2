// FindBFEncrypt.java - Find BF_encrypt by searching for the Feistel network pattern
// BF_encrypt does 16 rounds of: left ^= P[i]; right ^= F(left); swap(left,right)
// The F function accesses the S-boxes at P-box+72 bytes offset
// We find BF_encrypt by looking for callers of BF_set_key (FUN_1410ec460)
// since the same code module will contain BF_encrypt
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class FindBFEncrypt extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address imageBase = currentProgram.getImageBase();

        // FUN_14058b8d0 calls BF_set_key and also likely calls BF_encrypt
        // Let's find ALL functions called by FUN_14058b8d0 and its callers
        // to identify the encrypt/decrypt functions

        // Also: look at FUN_1410f2ce0 which is called right after BF_set_key
        // in FUN_140601920 line 221: FUN_1410f2ce0(local_1078, local_11d0[0])
        // This is likely BF_encrypt or BF_cfb64_encrypt

        long[] funcsToAnalyze = {
            0x10f2ce0L,  // Called after BF_set_key in FUN_140601920
            0x10f18a0L,  // Called to decode base64 key
            0x10f5860L,  // Called to format something with key
            0x10ede60L,  // Called for cleanup
        };

        for (long offset : funcsToAnalyze) {
            Address addr = imageBase.add(offset);
            Function func = getFunctionAt(addr);
            if (func == null) func = getFunctionContaining(addr);
            if (func == null) {
                println("No function at offset 0x" + Long.toHexString(offset));
                continue;
            }

            println("\n==========================================");
            println("Function at 0x" + Long.toHexString(offset) + " = " + func.getName());
            println("==========================================");
            decompileAndPrint(func, 150);

            // Find callers
            Reference[] refs = getReferencesTo(func.getEntryPoint());
            if (refs.length > 0) {
                println("Callers (" + refs.length + "):");
                for (int i = 0; i < Math.min(refs.length, 10); i++) {
                    Function caller = getFunctionContaining(refs[i].getFromAddress());
                    if (caller != null) println("  " + caller.getName() + " at " + caller.getEntryPoint());
                }
            }
        }

        // Now find the ENCRYPT function used for network packets
        // We know FUN_14058b8d0 stores the BF_KEY at some offset in a structure
        // The encrypt function will READ from that same structure
        // Let's look at the other callers of FUN_14058b8d0's parent

        // FUN_14058b8d0 callers: FUN_140571f80, FUN_14058b770
        // Let's decompile these
        println("\n==========================================");
        println("Callers of the crypto setup function");
        println("==========================================");

        long[] setupCallers = {
            0x571f80L,   // FUN_140571f80
            0x58b770L,   // FUN_14058b770
        };

        for (long offset : setupCallers) {
            Address addr = imageBase.add(offset);
            Function func = getFunctionAt(addr);
            if (func == null) func = getFunctionContaining(addr);
            if (func == null) continue;

            println("\n--- " + func.getName() + " ---");
            decompileAndPrint(func, 200);
        }

        // KEY: Find FUN_1410f2ce0 - this is likely BF_cfb64_encrypt or BF_ofb64_encrypt
        // because it's called with (BF_KEY, data) right after key setup
        println("\n==========================================");
        println("CRITICAL: FUN_1410f2ce0 (called after BF_set_key)");
        println("This is likely the encrypt/decrypt function!");
        println("==========================================");

        Address encAddr = imageBase.add(0x10f2ce0L);
        Function encFunc = getFunctionAt(encAddr);
        if (encFunc != null) {
            decompileAndPrint(encFunc, 200);

            // Find ALL callers - these are the places that encrypt/decrypt packets
            Reference[] refs = getReferencesTo(encFunc.getEntryPoint());
            println("\nAll callers of encrypt function (" + refs.length + "):");
            for (Reference ref : refs) {
                Function caller = getFunctionContaining(ref.getFromAddress());
                if (caller != null) {
                    println("  " + caller.getName() + " at " + caller.getEntryPoint() +
                            " (call at " + ref.getFromAddress() + ")");
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
                println("--- Decompiled (" + lines.length + " lines) ---");
                for (int i = 0; i < Math.min(lines.length, maxLines); i++) {
                    println(lines[i]);
                }
                if (lines.length > maxLines) println("... (" + (lines.length - maxLines) + " more lines)");
            }
            decomp.dispose();
        } catch (Exception e) {
            println("Decompile failed: " + e.getMessage());
        }
    }
}
