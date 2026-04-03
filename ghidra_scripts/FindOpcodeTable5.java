//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.util.*;

/**
 * FindOpcodeTable5 - Dump the full vtable and trace the game opcode dispatch
 *
 * Known: FUN_14057dce0 is at data address 0x1419478D0
 * The vtable is at 0x141A49518 (interface with handlers for packet processing)
 *
 * Need to:
 * 1. Dump the full vtable at 0x1419478D0 area (going back to find the base)
 * 2. Trace what calls the data handlers after reassembly
 * 3. The game opcode dispatch might be in a completely different subsystem -
 *    after ENet delivers a full message, the game layer reads opcode byte and dispatches
 */
public class FindOpcodeTable5 extends GhidraScript {

    private DecompInterface decomp;

    @Override
    public void run() throws Exception {
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // Phase 1: Dump the full vtable starting from 0x141947770 (= 0x1419478D0 - 0x160)
        println("=== Phase 1: Full vtable dump (base = 0x1419478D0 - 0x160 = 0x141947770) ===");
        long vtableBase = 0x1419478D0L - 0x160L;
        for (int i = 0; i < 64; i++) {
            long entryAddr = vtableBase + i * 8;
            try {
                Address ea = toAddr(entryAddr);
                long val = currentProgram.getMemory().getLong(ea);
                if (val > 0x140000000L && val < 0x142000000L) {
                    Function f = getFunctionAt(toAddr(val));
                    println(String.format("  vtable[%d] offset=0x%03X  addr=0x%X -> 0x%X %s", i, i * 8,
                        entryAddr, val, f != null ? f.getName() + " (size=" + f.getBody().getNumAddresses() + ")" : ""));
                } else {
                    println(String.format("  vtable[%d] offset=0x%03X  addr=0x%X -> 0x%X (not a func ptr)", i, i * 8,
                        entryAddr, val));
                }
            } catch (Exception e) { break; }
        }

        // Phase 2: The game message handler chain
        // After ENet reassembly, data arrives at FUN_14057dce0 which calls
        // FUN_14056e310(param_1 + 0x150, data) - this queues the message
        // Then a consumer thread picks it up and processes it
        // The consumer likely calls through the vtable at param_1+0x150's class

        // Let's find who dequeues and processes the data
        // FUN_14056e310 is the enqueue function
        // Its counterpart (dequeue) should be nearby
        println("\n=== Phase 2: Xrefs to FUN_14056e310 (enqueue) ===");
        Address enqAddr = toAddr(0x14056e310L);
        for (Reference ref : getReferencesTo(enqAddr)) {
            Function caller = getFunctionContaining(ref.getFromAddress());
            if (caller != null) {
                println("  Called from " + ref.getFromAddress() + " in " + caller.getName() +
                    " at " + caller.getEntryPoint() + " size=" + caller.getBody().getNumAddresses());
            }
        }

        // Phase 3: Decompile FUN_14056e310 to understand the queue structure
        println("\n=== Phase 3: FUN_14056e310 (enqueue function) ===");
        decompFull(0x14056e310L, 80);

        // Phase 4: Find the dequeue/consumer by looking for functions that read from
        // the same queue data structure. The queue is at param_1+0x150 offset.
        // Look for xrefs to FUN_14056e310's siblings (functions in the same class)
        println("\n=== Phase 4: Functions near FUN_14056e310 (same module) ===");
        for (long addr = 0x14056e200L; addr < 0x14056e400L; ) {
            Function f = getFunctionAt(toAddr(addr));
            if (f != null) {
                println("  " + f.getName() + " at " + f.getEntryPoint() +
                    " size=" + f.getBody().getNumAddresses());
                addr = f.getEntryPoint().getOffset() + f.getBody().getNumAddresses();
            } else {
                addr++;
            }
        }

        // Phase 5: The actual game-level opcode dispatch
        // In LoL, after ENet delivers a complete message buffer, the game reads:
        //   byte opcode = buffer[0];  (or after some header)
        //   handler_for_opcode[opcode]->process(buffer+1, length-1);
        //
        // This is typically done via a registered handler map:
        //   std::map<uint8_t, IPacketHandler*> or
        //   std::function<void(...)> handlers[256];
        //
        // Let's search for the classic LoL game packet handler registration
        // In LENet/older versions, this was via PacketNotifier with handler registration
        //
        // Search for functions that take a byte value and look it up in a container
        // The container could be a std::map (red-black tree) or std::unordered_map

        // Look for functions referencing game opcode strings or known packet names
        // LoL packets often have debug strings like "KeyCheck", "Ping", "ViewRequest", etc.
        println("\n=== Phase 5: Searching for game packet name strings ===");
        String[] packetNames = {"KeyCheck", "keycheck", "Ping_Load_Info", "SynchVersion",
            "QueryStatus", "ViewRequest", "CharacterCreate", "SpawnPacket",
            "S2C_", "C2S_", "PKT_", "GamePacket", "PacketType", "opcode",
            "packet_type", "handlePacket", "OnPacket", "processPacket"};
        for (String name : packetNames) {
            // Search in memory for the string
            Address start = currentProgram.getMinAddress();
            Address end = currentProgram.getMaxAddress();
            Address found = currentProgram.getMemory().findBytes(start,
                name.getBytes(), null, true, monitor);
            if (found != null) {
                println("  Found '" + name + "' at " + found);
                // Find xrefs to this string
                for (Reference ref : getReferencesTo(found)) {
                    Function caller = getFunctionContaining(ref.getFromAddress());
                    println("    Referenced from " + ref.getFromAddress() +
                        (caller != null ? " in " + caller.getName() + "@" + caller.getEntryPoint() : ""));
                }
            }
        }

        // Phase 6: Broader string search for "C2S" and "S2C" packet prefixes
        println("\n=== Phase 6: Search for C2S/S2C packet type strings ===");
        Address searchAddr = currentProgram.getMinAddress();
        int found = 0;
        while (searchAddr != null && found < 30) {
            searchAddr = currentProgram.getMemory().findBytes(searchAddr,
                "C2S_".getBytes(), null, true, monitor);
            if (searchAddr != null) {
                // Read a few bytes to get the full string name
                byte[] buf = new byte[64];
                try {
                    currentProgram.getMemory().getBytes(searchAddr, buf);
                    String str = new String(buf).split("\0")[0];
                    if (str.length() > 4 && str.length() < 60) {
                        println("  " + searchAddr + ": " + str);
                        found++;
                    }
                } catch (Exception e) {}
                searchAddr = searchAddr.add(1);
            }
        }

        searchAddr = currentProgram.getMinAddress();
        found = 0;
        while (searchAddr != null && found < 30) {
            searchAddr = currentProgram.getMemory().findBytes(searchAddr,
                "S2C_".getBytes(), null, true, monitor);
            if (searchAddr != null) {
                byte[] buf = new byte[64];
                try {
                    currentProgram.getMemory().getBytes(searchAddr, buf);
                    String str = new String(buf).split("\0")[0];
                    if (str.length() > 4 && str.length() < 60) {
                        println("  " + searchAddr + ": " + str);
                        found++;
                    }
                } catch (Exception e) {}
                searchAddr = searchAddr.add(1);
            }
        }

        println("\n=== DONE ===");
        decomp.dispose();
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
