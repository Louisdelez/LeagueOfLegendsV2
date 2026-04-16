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
 * FindOpcodeTable7 - Find the packet handler table via the batched message processing
 *
 * New approach: The packet data flows like this:
 * 1. ENet delivers raw data
 * 2. FUN_14057d4c0 reads the batched framing (0x02 + len + items + 0x18)
 * 3. Each item in the batch is a game packet with an opcode
 * 4. Something dispatches each item based on its opcode
 *
 * The items array from FUN_14057d4c0 is stored in param_2 and returned to:
 * - FUN_14057dd10 which calls FUN_14058ded0 and FUN_14058d960
 * - FUN_14057dec0 which calls FUN_14058d350
 *
 * These functions BUILD the packet objects. The actual dispatch must happen
 * when these objects are CONSUMED.
 *
 * Alternative approach: Search for large function arrays in .rdata
 * that could be handler tables (256 or more function pointers in a row).
 */
public class FindOpcodeTable7 extends GhidraScript {

    private DecompInterface decomp;

    @Override
    public void run() throws Exception {
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // Phase 1: Search for large function pointer arrays in .rdata
        // A handler table would be 256 function pointers (256 * 8 = 2048 bytes)
        // or a smaller table if not all opcodes are used
        println("=== Phase 1: Searching for function pointer arrays in .rdata ===");
        findFuncPtrArrays(0x141800000L, 0x141e00000L, 20); // min 20 entries

        // Phase 2: The consumer of the batched items
        // FUN_14057dd10 builds items then what? Let's look at what happens AFTER
        // Check FUN_14058b8d0 which also calls FUN_14056e310 (enqueue)
        println("\n=== Phase 2: FUN_14058b8d0 (also calls enqueue) ===");
        decompFull(0x14058b8d0L, 80);

        // Phase 3: Search for "PacketNotifier" or "handlePacket" strings
        println("\n=== Phase 3: Searching for handler-related strings ===");
        String[] patterns = {"Packet", "packet", "Handler", "handler", "Dispatch", "dispatch",
            "Opcode", "opcode", "Protocol", "protocol", "KeyCheck"};
        for (String pat : patterns) {
            Address addr = currentProgram.getMemory().findBytes(currentProgram.getMinAddress(),
                pat.getBytes(), null, true, monitor);
            while (addr != null) {
                byte[] buf = new byte[80];
                try {
                    currentProgram.getMemory().getBytes(addr, buf);
                    String str = new String(buf).split("\0")[0];
                    if (str.length() > 4 && str.length() < 75) {
                        // Check for useful context
                        boolean useful = str.contains("Notif") || str.contains("Handle") ||
                            str.contains("Dispatch") || str.contains("Register") ||
                            str.contains("KeyCheck") || str.contains("Process") ||
                            str.contains("handler") || str.contains("opcode") ||
                            (str.startsWith("Packet") && !str.contains("@@@"));
                        if (useful) {
                            println("  " + addr + ": " + str);
                            // Show xrefs
                            for (Reference ref : getReferencesTo(addr)) {
                                Function f = getFunctionContaining(ref.getFromAddress());
                                if (f != null) {
                                    println("    -> " + f.getName() + "@" + f.getEntryPoint() +
                                        " size=" + f.getBody().getNumAddresses());
                                }
                            }
                        }
                    }
                } catch (Exception e) {}
                addr = currentProgram.getMemory().findBytes(addr.add(1), pat.getBytes(), null, true, monitor);
            }
        }

        // Phase 4: The items returned by FUN_14057d4c0 are 16-byte structures
        // (4 ints each). The third int field is used for dispatch.
        // Let's look at how the items are consumed.
        // FUN_14057dd10 calls FUN_14058ded0 and FUN_14058d960 with (param_1, param_2)
        // where param_2 contains the items array.
        // FUN_14058d350/d960/ded0 BUILD network message objects from items.
        // These objects are then sent/dispatched. Let's trace what they produce.

        // FUN_14058d350 etc. call functions that create objects and add them to queues
        // The objects have a specific type/ID that corresponds to the opcode
        // Let's look at what objects FUN_14058d350 creates

        println("\n=== Phase 4: Callees of FUN_14058d350 (packet builder) ===");
        Function f = getFunctionAt(toAddr(0x14058d350L));
        if (f != null) {
            Set<String> seen = new HashSet<>();
            for (Instruction inst : currentProgram.getListing().getInstructions(f.getBody(), true)) {
                if (inst.getMnemonicString().equals("CALL")) {
                    for (Reference ref : inst.getReferencesFrom()) {
                        Function target = getFunctionAt(ref.getToAddress());
                        if (target != null && seen.add(target.getEntryPoint().toString())) {
                            println("  " + target.getName() + " at " + target.getEntryPoint() +
                                " size=" + target.getBody().getNumAddresses());
                        }
                    }
                }
            }
        }

        // Phase 5: Maybe the opcode dispatch is at a higher level altogether
        // Let's check FUN_1405883d0 (the consumer function mentioned by user)
        // and see what it does with the received data
        println("\n=== Phase 5: FUN_1405883d0 (packet consumer) full decompile ===");
        decompFull(0x1405883d0L, 120);

        // Phase 6: Check the batched item structure
        // In FUN_14057d4c0:
        //   Reads 1 byte -> 0x02 marker
        //   Reads 4 bytes -> count (local_res20[0])
        //   Allocates count * 16 bytes
        //   For each item: calls FUN_14055b9a0(plVar1, item_ptr)
        // The per-item reader FUN_14055b9a0 reads the actual packet content
        // Let's decompile it
        println("\n=== Phase 6: FUN_14055b9a0 (per-item reader in batch) ===");
        decompFull(0x14055b9a0L, 120);

        println("\n=== DONE ===");
        decomp.dispose();
    }

    private void findFuncPtrArrays(long start, long end, int minEntries) {
        // Scan .rdata for sequences of valid function pointers
        int consecutiveCount = 0;
        long arrayStart = 0;
        long lastAddr = start;

        for (long addr = start; addr < end; addr += 8) {
            try {
                Address a = toAddr(addr);
                long val = currentProgram.getMemory().getLong(a);
                if (val > 0x140000000L && val < 0x142000000L) {
                    Function f = getFunctionAt(toAddr(val));
                    if (f != null) {
                        if (consecutiveCount == 0) arrayStart = addr;
                        consecutiveCount++;
                        continue;
                    }
                }
            } catch (Exception e) {}

            if (consecutiveCount >= minEntries) {
                println(String.format("  FUNC PTR ARRAY at 0x%X: %d consecutive entries", arrayStart, consecutiveCount));
                // Dump first and last few entries
                for (int i = 0; i < Math.min(5, consecutiveCount); i++) {
                    dumpEntry(arrayStart + i * 8, i);
                }
                if (consecutiveCount > 10) println("    ...");
                for (int i = Math.max(5, consecutiveCount - 3); i < consecutiveCount; i++) {
                    dumpEntry(arrayStart + i * 8, i);
                }
            }
            consecutiveCount = 0;
        }
    }

    private void dumpEntry(long addr, int idx) {
        try {
            long val = currentProgram.getMemory().getLong(toAddr(addr));
            Function f = getFunctionAt(toAddr(val));
            println(String.format("    [%d] 0x%X -> 0x%X %s", idx, addr, val,
                f != null ? f.getName() + " (size=" + f.getBody().getNumAddresses() + ")" : ""));
        } catch (Exception e) {}
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
