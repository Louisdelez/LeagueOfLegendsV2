//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.util.*;

/**
 * FindOpcodeTable8 - Trace the game data handler vtable
 *
 * FUN_1405883d0 (consumer) dispatches game data (type 2) via:
 *   plVar3 = *(param_1 + 0x168)
 *   (**(code **)(*plVar3 + 0x10))(plVar3, data, ...)
 *
 * Need to find what class is at param_1+0x168 and what vtable[2] (offset 0x10) does.
 * That's the function that receives individual game packets and must dispatch by opcode.
 *
 * Strategy:
 * 1. Find who writes to offset 0x168 of the object
 * 2. Find the vtable of that class
 * 3. Decompile vtable[2] (the handler)
 */
public class FindOpcodeTable8 extends GhidraScript {

    private DecompInterface decomp;

    @Override
    public void run() throws Exception {
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // Phase 1: Search for where offset 0x168 is written
        // This would be in the constructor or initialization of the packet processing object
        // The consumer is FUN_1405883d0, which takes param_1 as the object
        // Look for xrefs to FUN_1405883d0 to find who creates the object
        println("=== Phase 1: Xrefs to FUN_1405883d0 (consumer) ===");
        for (Reference ref : getReferencesTo(toAddr(0x1405883d0L))) {
            Function f = getFunctionContaining(ref.getFromAddress());
            if (f != null) {
                println("  From " + ref.getFromAddress() + " in " + f.getName() +
                    "@" + f.getEntryPoint() + " size=" + f.getBody().getNumAddresses());
            } else {
                println("  From " + ref.getFromAddress() + " (data ref)");
            }
        }

        // Phase 2: Check the vtable at 0x141947770 (we found earlier)
        // offset 0x168 from the object -> the vtable pointer
        // But wait, offset 0x168 is an OBJECT pointer stored IN the host object,
        // not a vtable offset. The host object has at offset 0x168 a pointer to another object.
        // That other object has its own vtable.

        // Let's look at how the host object is constructed. The constructor likely initializes
        // offset 0x168 with a pointer to a game packet handler object.

        // Phase 2: Search for PacketRcv string and its referencing function
        println("\n=== Phase 2: FUN_140580870 (PacketRcv handler) ===");
        decompFull(0x140580870L, 100);

        // Phase 3: Decompile FUN_14057e7c0 (vtable[45] = offset 0x168)
        // Wait - vtable[45] offset=0x168 in the vtable at 0x141947770 -> 0x14057E7C0
        // That matches! vtable offset 0x168 is FUN_14057e7c0
        // But in the consumer, offset 0x168 is a DATA field, not a vtable call.
        // The consumer does: plVar3 = *(param_1 + 0x168); (**(code **)(*plVar3 + 0x10))(plVar3, ...)
        // So param_1+0x168 is a POINTER to another object, and that object's vtable+0x10 is called.

        // Let's find who sets param_1+0x168.
        // The constructor of the network subsystem likely does:
        //   this->field_0x168 = new GamePacketHandler(...);
        // Search for MOV [reg+0x168], reg patterns in the 1405xxxxx range

        println("\n=== Phase 3: Searching for writes to offset 0x168 ===");
        findOffsetWrites(0x14056e000L, 0x14059a000L, 0x168);

        // Also search offset 0x128 (the other handler)
        println("\n=== Phase 3b: Searching for writes to offset 0x128 ===");
        findOffsetWrites(0x14056e000L, 0x14059a000L, 0x128);

        // Phase 4: The "{PacketID} {Size}bytes" format string at 141957a91
        // Let's find who references it and decode the PacketID handling
        println("\n=== Phase 4: Xrefs to PacketID format string ===");
        Address pktIdStr = currentProgram.getMemory().findBytes(currentProgram.getMinAddress(),
            "PacketID".getBytes(), null, true, monitor);
        if (pktIdStr != null) {
            println("Found 'PacketID' at " + pktIdStr);
            // Search wider for PacketID refs
            for (Reference ref : getReferencesTo(pktIdStr)) {
                Function f = getFunctionContaining(ref.getFromAddress());
                println("  Ref from " + ref.getFromAddress() +
                    (f != null ? " in " + f.getName() + "@" + f.getEntryPoint() +
                    " size=" + f.getBody().getNumAddresses() : ""));
                if (f != null && f.getBody().getNumAddresses() > 100) {
                    decompFull(f.getEntryPoint().getOffset(), 80);
                }
            }
        }

        // Phase 5: Search for the string "S2C_QueryStatusAns" which is the response
        // to KeyCheck - this is a well-known early packet
        println("\n=== Phase 5: Searching for QueryStatus and KeyCheck strings ===");
        searchAndTrace("QueryStatus");
        searchAndTrace("SynchVersion");
        searchAndTrace("LoadScreen");

        // Phase 6: The handler at param_1+0x168 has vtable+0x10.
        // In LoL, the game packet handler is typically GamePacketNotifier which has a
        // OnGamePacket(data, len, channel) method.
        // The opcode is the FIRST BYTE of the data buffer.
        // Then it looks up handler[opcode] and calls it.
        // This lookup might use a std::map<uint16_t, handler> (red-black tree).
        //
        // Since we know FUN_14058d350/d960/ded0 are called from FUN_14057dd10/dec0
        // and they BUILD packet objects, the opcode must be set during construction.
        // Let's look at what fields they set that could be the opcode.

        // Actually, let me re-read the consumer more carefully.
        // In the consumer (FUN_1405883d0), for type 2:
        //   It iterates through batch items (stride = 7 * 8 = 56 bytes each)
        //   For each item: puVar7[-5], puVar7[-3], *puVar7, puVar7+2...
        //   And calls vtable+0x10 with these fields
        //
        // The batch items come from the queue which was filled by:
        //   FUN_14057dce0 -> FUN_14056e310(param_1+0x150, data)
        //   FUN_14057dd10 -> FUN_14058ded0/d960
        //   FUN_14057dec0 -> FUN_14058d350
        //
        // These fill queue entries with parsed packet data.
        // The queue entry likely contains: {channel, netid, data_ptr, data_len, opcode?, ...}

        // Let's look at what FUN_14058d350 writes to the queue
        println("\n=== Phase 6: First 150 lines of FUN_14058d350 ===");
        decompFull(0x14058d350L, 150);

        println("\n=== DONE ===");
        decomp.dispose();
    }

    private void findOffsetWrites(long start, long end, int offset) {
        String hexOffset = String.format("0x%x", offset);
        for (long addr = start; addr < end; ) {
            Address a = toAddr(addr);
            Instruction inst = currentProgram.getListing().getInstructionAt(a);
            if (inst != null) {
                if (inst.getMnemonicString().equals("MOV") && inst.getNumOperands() >= 2) {
                    String op0 = inst.getDefaultOperandRepresentation(0);
                    // Check if writing to [reg + 0x168]
                    if (op0.contains(hexOffset) || op0.contains("0x" + Integer.toHexString(offset).toUpperCase())) {
                        Function f = getFunctionContaining(a);
                        println(String.format("  WRITE at %s: %s  (in %s)",
                            a, inst, f != null ? f.getName() + "@" + f.getEntryPoint() : "?"));
                    }
                }
                addr += inst.getLength();
            } else { addr++; }
        }
    }

    private void searchAndTrace(String name) {
        Address addr = currentProgram.getMemory().findBytes(currentProgram.getMinAddress(),
            name.getBytes(), null, true, monitor);
        if (addr != null) {
            println("  Found '" + name + "' at " + addr);
            for (Reference ref : getReferencesTo(addr)) {
                Function f = getFunctionContaining(ref.getFromAddress());
                if (f != null) {
                    println("    -> " + f.getName() + "@" + f.getEntryPoint() +
                        " size=" + f.getBody().getNumAddresses());
                }
            }
        } else {
            println("  '" + name + "' not found");
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
