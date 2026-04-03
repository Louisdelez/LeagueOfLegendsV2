//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.util.*;

/**
 * FindOpcodeTable9 - Decompile FUN_14058a4f0 (network init) and trace the handler objects
 *
 * FUN_14058a4f0 writes to offset 0x168 and 0x128 of the host object.
 * These are the game packet handler objects whose vtable+0x10 is the dispatch function.
 */
public class FindOpcodeTable9 extends GhidraScript {

    private DecompInterface decomp;

    @Override
    public void run() throws Exception {
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // Phase 1: Decompile FUN_14058a4f0 around the 0x168/0x128 writes
        println("=== Phase 1: FUN_14058a4f0 (network subsystem init) ===");
        Function f = getFunctionAt(toAddr(0x14058a4f0L));
        if (f != null) {
            println("Size: " + f.getBody().getNumAddresses());
            DecompileResults r = decomp.decompileFunction(f, 600, monitor);
            if (r.decompileCompleted()) {
                String code = r.getDecompiledFunction().getC();
                String[] lines = code.split("\n");
                // Print lines around 0x168 and 0x128 mentions
                for (int i = 0; i < lines.length; i++) {
                    if (lines[i].contains("0x168") || lines[i].contains("0x128") ||
                        lines[i].contains("0x160") || lines[i].contains("vtable") ||
                        (i > 0 && (lines[i-1].contains("0x168") || lines[i-1].contains("0x128"))) ||
                        (i < lines.length-1 && (lines[i+1].contains("0x168") || lines[i+1].contains("0x128")))) {
                        println(String.format("  [%d] %s", i, lines[i]));
                    }
                }
                // Also print the full decompilation (first 400 lines)
                println("\n--- Full decompilation ---");
                for (int i = 0; i < Math.min(400, lines.length); i++) println("  " + lines[i]);
                if (lines.length > 400) println("  ... (" + (lines.length - 400) + " more lines)");
            }
        }

        // Phase 2: Once we know what object is at 0x168, find its vtable
        // and decompile vtable+0x10 (the dispatch function)
        // For now, also look at the instructions around 14058ac93 directly
        println("\n=== Phase 2: Disasm around 14058ac93 (write to 0x168) ===");
        disasmRange(0x14058ac60L, 0x14058ad20L);

        // Phase 3: Also check FUN_140588050 which is called from the PacketRcv handler
        // This might format/log packet info including the opcode
        println("\n=== Phase 3: FUN_140588050 (called with packet data for logging) ===");
        decompFull(0x140588050L, 100);

        println("\n=== DONE ===");
        decomp.dispose();
    }

    private void disasmRange(long start, long end) {
        for (long addr = start; addr < end; ) {
            Address a = toAddr(addr);
            Instruction inst = currentProgram.getListing().getInstructionAt(a);
            if (inst != null) {
                println(String.format("  %s: %s", a, inst));
                addr += inst.getLength();
            } else { addr++; }
        }
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
