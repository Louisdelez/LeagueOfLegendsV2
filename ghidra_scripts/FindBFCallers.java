// FindBFCallers.java - Find callers of BF_set_key and BF_encrypt
// BF_set_key = FUN_1410ec460 (offset 0x10ec460) and FUN_14174f140 (offset 0x174f140)
// Find ALL callers of these functions, then decompile the callers
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class FindBFCallers extends GhidraScript {

    @Override
    public void run() throws Exception {
        Address imageBase = currentProgram.getImageBase();
        println("Image base: " + imageBase);

        // Known Blowfish functions
        long[] bfFuncOffsets = {
            0x10ec460L,  // BF_set_key version 1
            0x174f140L,  // BF_set_key version 2 (OpenSSL)
            0x1725300L,  // Likely EVP_bf_cbc or similar
        };
        String[] bfFuncNames = { "BF_set_key_v1", "BF_set_key_v2_openssl", "EVP_bf_xxx" };

        for (int i = 0; i < bfFuncOffsets.length; i++) {
            Address funcAddr = imageBase.add(bfFuncOffsets[i]);
            println("\n==========================================");
            println("Finding callers of " + bfFuncNames[i] + " at " + funcAddr);
            println("==========================================");

            Function func = getFunctionAt(funcAddr);
            if (func == null) {
                println("  No function at this address, trying nearby...");
                func = getFunctionContaining(funcAddr);
                if (func != null) {
                    println("  Found containing function: " + func.getName() + " at " + func.getEntryPoint());
                }
            }

            // Find all references TO this function
            Reference[] refs = getReferencesTo(funcAddr);
            println("  References: " + refs.length);

            Set<String> callerFuncs = new HashSet<>();
            for (Reference ref : refs) {
                Address fromAddr = ref.getFromAddress();
                Function caller = getFunctionContaining(fromAddr);
                if (caller != null && !callerFuncs.contains(caller.getName())) {
                    callerFuncs.add(caller.getName());
                    println("\n  CALLER: " + caller.getName() + " at " + caller.getEntryPoint());
                    println("  Call at: " + fromAddr + " (offset +0x" + Long.toHexString(fromAddr.subtract(caller.getEntryPoint())) + ")");

                    // Decompile the caller
                    decompileAndPrint(caller, 100);

                    // Also find callers of the caller (2 levels up)
                    Reference[] callerRefs = getReferencesTo(caller.getEntryPoint());
                    if (callerRefs.length > 0 && callerRefs.length < 20) {
                        println("  Callers of " + caller.getName() + " (" + callerRefs.length + "):");
                        for (Reference cref : callerRefs) {
                            Function grandCaller = getFunctionContaining(cref.getFromAddress());
                            if (grandCaller != null) {
                                println("    " + grandCaller.getName() + " at " + grandCaller.getEntryPoint());
                            }
                        }
                    }
                }
            }

            if (callerFuncs.isEmpty()) {
                println("  No callers found! Function may be called indirectly (via function pointer).");

                // Search for the function address as a data reference
                byte[] addrBytes = new byte[8];
                long addr = funcAddr.getOffset();
                for (int b = 0; b < 8; b++) {
                    addrBytes[b] = (byte)(addr & 0xFF);
                    addr >>= 8;
                }

                println("  Searching for address pattern: " + bytesToHex(addrBytes));
                Address searchStart = currentProgram.getMinAddress();
                Address searchEnd = currentProgram.getMaxAddress();
                Address found = currentProgram.getMemory().findBytes(searchStart, searchEnd, addrBytes, null, true, monitor);
                int count = 0;
                while (found != null && count < 10) {
                    println("  Address ref at: " + found);
                    Reference[] dataRefs = getReferencesTo(found);
                    for (Reference dr : dataRefs) {
                        Function f = getFunctionContaining(dr.getFromAddress());
                        println("    Referenced by: " + (f != null ? f.getName() : "<none>") + " at " + dr.getFromAddress());
                    }
                    found = currentProgram.getMemory().findBytes(found.add(1), searchEnd, addrBytes, null, true, monitor);
                    count++;
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
                println("  --- Decompiled " + func.getName() + " (" + lines.length + " lines) ---");
                for (int i = 0; i < Math.min(lines.length, maxLines); i++) {
                    println("  " + lines[i]);
                }
                if (lines.length > maxLines) {
                    println("  ... (" + (lines.length - maxLines) + " more lines)");
                }
            }
            decomp.dispose();
        } catch (Exception e) {
            println("  Decompile failed: " + e.getMessage());
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b & 0xFF));
        }
        return sb.toString().trim();
    }
}
