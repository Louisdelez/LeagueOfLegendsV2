// FindNetworkSend.java - Find the function that builds and sends the 519B packet
// Strategy: stub.dll loads WSASendTo dynamically. The address is stored somewhere.
// We search for code that calls a function pointer with typical sendto parameters.
// Also: search for the constant 519 (0x207) or 511 (0x1FF) in the code.
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import java.util.*;

public class FindNetworkSend extends GhidraScript {

    @Override
    public void run() throws Exception {
        Address imageBase = currentProgram.getImageBase();
        println("Image base: " + imageBase);

        // APPROACH 1: Search for the constant 519 (0x207) in code
        // The packet size 519 must appear somewhere as a buffer allocation or comparison
        println("\n=== Searching for constant 519 (0x207) in code ===");
        findConstantInCode(0x207, "519 (packet size)");

        // Also search for 511 = 519 - 8 (payload size without header)
        println("\n=== Searching for constant 511 (0x1FF) ===");
        findConstantInCode(0x1FF, "511 (payload size)");

        // Search for 503 = 519 - 16 (payload without header+checksum)
        println("\n=== Searching for constant 503 (0x1F7) ===");
        findConstantInCode(0x1F7, "503");

        // APPROACH 2: Search for the BF_set_key callers that we already found
        // FUN_1406e5fd0 calls BF_cfb64_encrypt — it's a network function
        // FUN_1406db490 also calls BF_cfb64_encrypt
        // FUN_1406dcc80 also calls BF_cfb64_encrypt
        // Let's decompile these and their callers

        println("\n=== Decompiling network crypto functions ===");
        long[] networkFuncs = {
            0x6e5fd0L,  // Calls BF_cfb64_encrypt
            0x6db490L,  // Calls BF_cfb64_encrypt
            0x6dcc80L,  // Calls BF_cfb64_encrypt
            0x6c7d10L,  // Caller of FUN_1406e5fd0 (from previous analysis)
        };
        String[] names = { "NetCrypto1", "NetCrypto2", "NetCrypto3", "NetCryptoParent" };

        for (int i = 0; i < networkFuncs.length; i++) {
            Address addr = imageBase.add(networkFuncs[i]);
            Function func = getFunctionAt(addr);
            if (func == null) func = getFunctionContaining(addr);
            if (func == null) { println("No function at 0x" + Long.toHexString(networkFuncs[i])); continue; }

            println("\n==========================================");
            println(names[i] + " = " + func.getName() + " at " + func.getEntryPoint());
            println("==========================================");

            decompileAndPrint(func, 120);

            // Find callers
            Reference[] refs = getReferencesTo(func.getEntryPoint());
            if (refs.length > 0 && refs.length < 20) {
                println("Callers (" + refs.length + "):");
                Set<String> seen = new HashSet<>();
                for (Reference ref : refs) {
                    Function caller = getFunctionContaining(ref.getFromAddress());
                    if (caller != null && !seen.contains(caller.getName())) {
                        seen.add(caller.getName());
                        println("  " + caller.getName() + " at " + caller.getEntryPoint());
                    }
                }
            }
        }

        // APPROACH 3: Find functions that reference "sendto" or "WSASendTo" strings
        println("\n=== Searching for sendto/WSASendTo string references ===");
        String[] searchStrings = { "sendto", "WSASendTo", "WSARecvFrom", "recvfrom" };
        for (String s : searchStrings) {
            byte[] pattern = s.getBytes();
            Address found = currentProgram.getMemory().findBytes(
                currentProgram.getMinAddress(), currentProgram.getMaxAddress(),
                pattern, null, true, monitor);
            while (found != null) {
                // Check if it's a proper null-terminated string
                try {
                    byte nextByte = currentProgram.getMemory().getByte(found.add(s.length()));
                    if (nextByte == 0) {
                        println("String '" + s + "' at " + found);
                        Reference[] refs = getReferencesTo(found);
                        for (Reference ref : refs) {
                            Function f = getFunctionContaining(ref.getFromAddress());
                            if (f != null) {
                                println("  Referenced by " + f.getName() + " at " + ref.getFromAddress());
                            }
                        }
                    }
                } catch (Exception e) {}
                found = currentProgram.getMemory().findBytes(
                    found.add(1), currentProgram.getMaxAddress(),
                    pattern, null, true, monitor);
            }
        }

        println("\n=== DONE ===");
    }

    private void findConstantInCode(long value, String name) {
        // Search for the value as an immediate operand in instructions
        InstructionIterator iter = currentProgram.getListing().getInstructions(true);
        int count = 0;
        Set<String> funcsSeen = new HashSet<>();

        while (iter.hasNext() && count < 20) {
            Instruction inst = iter.next();
            for (int i = 0; i < inst.getNumOperands(); i++) {
                Object[] opObjects = inst.getOpObjects(i);
                for (Object obj : opObjects) {
                    if (obj instanceof Scalar) {
                        long val = ((Scalar) obj).getValue();
                        if (val == value) {
                            Function func = getFunctionContaining(inst.getAddress());
                            String funcName = func != null ? func.getName() : "<none>";
                            if (!funcsSeen.contains(funcName)) {
                                funcsSeen.add(funcName);
                                println("  " + name + " found at " + inst.getAddress() +
                                        " in " + funcName + ": " + inst.toString());
                                count++;
                                if (func != null && count <= 5) {
                                    decompileAndPrint(func, 60);
                                }
                            }
                        }
                    }
                }
            }
        }
        if (count == 0) println("  Not found in instruction operands");
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
