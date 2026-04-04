//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.util.*;

/**
 * DumpOpcodeMap - Read the jump table at FUN_140955c20 and extract opcode -> handler map
 *
 * Structure (MSVC switch):
 *   Base opcode = 0x0A (subtracted at ADD ECX, -0xa)
 *   Byte index table at 0x140957120 (250 entries, one byte each)
 *   Dword offset table at 0x1409570C4 (N entries, 4 bytes each, relative offsets)
 *   Image base = 0x140000000
 *
 * Also handles the secondary switches for opcodes >= 0x10B
 */
public class DumpOpcodeMap extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        println("=== Game Packet Opcode Map (LoL 16.6 / FUN_140955c20) ===");
        println("Opcode source: *(ushort*)(packet + 8)");
        println("");

        long imageBase = 0x140000000L;

        // Read the byte index table (maps opcode-0x0A to a case index)
        long byteTableAddr = imageBase + 0x957120L;
        int byteTableSize = 0xFA; // 0xF9 + 1 = 250 entries (opcodes 0x0A to 0x103)
        byte[] byteTable = new byte[byteTableSize];
        currentProgram.getMemory().getBytes(toAddr(byteTableAddr), byteTable);

        // Read the dword offset table (maps case index to code offset)
        long dwordTableAddr = imageBase + 0x9570C4L;
        // Determine number of unique case indices
        int maxIdx = 0;
        for (int i = 0; i < byteTableSize; i++) {
            int idx = byteTable[i] & 0xFF;
            if (idx > maxIdx) maxIdx = idx;
        }
        println("Byte index table: " + byteTableSize + " entries, max index = " + maxIdx);

        int[] dwordTable = new int[maxIdx + 1];
        for (int i = 0; i <= maxIdx; i++) {
            dwordTable[i] = currentProgram.getMemory().getInt(toAddr(dwordTableAddr + i * 4));
        }

        // Map opcodes to handler addresses
        println("\n--- Opcode -> Handler mapping (first switch, opcodes 0x0A - 0x103) ---");
        Map<Long, List<Integer>> handlerToOpcodes = new TreeMap<>();

        for (int i = 0; i < byteTableSize; i++) {
            int opcode = 0x0A + i;
            int caseIdx = byteTable[i] & 0xFF;
            long handlerAddr = imageBase + (dwordTable[caseIdx] & 0xFFFFFFFFL);

            if (!handlerToOpcodes.containsKey(handlerAddr))
                handlerToOpcodes.put(handlerAddr, new ArrayList<>());
            handlerToOpcodes.get(handlerAddr).add(opcode);
        }

        // Find the default case handler (multiple opcodes map to it)
        long defaultHandler = 0;
        int maxCount = 0;
        for (Map.Entry<Long, List<Integer>> e : handlerToOpcodes.entrySet()) {
            if (e.getValue().size() > maxCount) {
                maxCount = e.getValue().size();
                defaultHandler = e.getKey();
            }
        }

        // Print non-default cases
        Map<Integer, Long> opcodeToHandler = new TreeMap<>();
        for (int i = 0; i < byteTableSize; i++) {
            int opcode = 0x0A + i;
            int caseIdx = byteTable[i] & 0xFF;
            long handlerAddr = imageBase + (dwordTable[caseIdx] & 0xFFFFFFFFL);
            if (handlerAddr != defaultHandler) {
                opcodeToHandler.put(opcode, handlerAddr);
            }
        }

        println(String.format("Default handler (unhandled opcodes): 0x%X", defaultHandler));
        println(String.format("Handled opcodes in first switch: %d", opcodeToHandler.size()));
        println("");

        for (Map.Entry<Integer, Long> e : opcodeToHandler.entrySet()) {
            int opcode = e.getKey();
            long addr = e.getValue();
            // Try to find what function is called at this address
            Function f = getFunctionContaining(toAddr(addr));
            String funcInfo = "";
            if (f != null && f.getEntryPoint().getOffset() == addr) {
                funcInfo = f.getName();
            }
            println(String.format("  opcode 0x%04X (%4d) -> jump target 0x%X %s",
                opcode, opcode, addr, funcInfo));
        }

        // Special cases outside the first switch:
        // opcode 0x10A -> handled separately (FUN_140963ae0)
        println(String.format("\n  opcode 0x%04X (%4d) -> FUN_140963ae0 (special case outside switch)",
            0x10A, 0x10A));

        // For opcodes >= 0x10B, there are more switch statements
        // Let's check the second switch at line 284 (opcodes >= 0x10B)
        println("\n--- Additional opcodes from secondary switches (from decompilation) ---");
        println("  opcode 0x0136 ( 310) -> falls through to default");
        println("  opcode 0x013E ( 318) -> FUN_1409d3610");
        println("  opcode 0x014A ( 330) -> FUN_1409d1ea0");
        println("  opcode 0x014F ( 335) -> FUN_1409d50d0");
        println("  opcode 0x016E ( 366) -> FUN_1409667a0");
        println("  opcode 0x0176 ( 374) -> inline check param_2+0x10 == 'A'");
        println("  opcode 0x0193 ( 403) -> FUN_140965440");
        println("  opcode 0x0197 ( 407) -> inline byte manipulation");
        println("  opcode 0x019F ( 415) -> FUN_140967b60");
        println("  opcode 0x01A7 ( 423) -> falls through to default");
        println("  opcode 0x01BF ( 447) -> falls through to default");
        println("  opcode 0x01C4 ( 452) -> FUN_1409d4450");
        println("  opcode 0x01CF ( 463) -> FUN_1409d2f70");
        println("  opcode 0x01D3 ( 467) -> FUN_140985ac0");
        println("  opcode 0x0224 ( 548) -> FUN_1409d1f70");
        println("  opcode 0x0227 ( 551) -> FUN_1409d5450");
        println("  opcode 0x0236 ( 566) -> FUN_1409662d0");
        println("  opcode 0x023B ( 571) -> inline");
        println("  opcode 0x0255 ( 597) -> inline byte manipulation");
        println("  opcode 0x0260 ( 608) -> FUN_140966fd0");
        println("  opcode 0x0268 ( 616) -> inline with piVar22");
        println("  opcode 0x0270 ( 624) -> inline with local_184");
        println("  opcode 0x0286 ( 646) -> FUN_140969b20");
        println("  opcode 0x028C ( 652) -> FUN_1409d1530");
        println("  opcode 0x028E ( 654) -> inline with local_17c");
        println("  opcode 0x0293 ( 659) -> FUN_140967530");
        println("  opcode 0x029C ( 668) -> inline with local_188");
        println("  opcode 0x02B2 ( 690) -> FUN_1409856e0");
        println("  opcode 0x02C0 ( 704) -> FUN_1409d1420");
        println("  opcode 0x02CA ( 714) -> inline byte manipulation");
        println("  opcode 0x02CD ( 717) -> inline with piVar27");
        println("  opcode 0x02D7 ( 727) -> FUN_1409d2ae0");
        println("  opcode 0x02E7 ( 743) -> inline with param_2+0x18");
        println("  opcode 0x02F0 ( 752) -> inline byte manipulation");
        println("  opcode 0x02F8 ( 760) -> FUN_1409d2650");
        println("  opcode 0x02FA ( 762) -> inline with DAT_141989600 lookup");
        println("  opcode 0x0305 ( 773) -> FUN_140966180");
        println("  opcode 0x031A ( 794) -> FUN_1409d1450");
        println("  opcode 0x0327 ( 807) -> FUN_1409d12a0");
        println("  opcode 0x0332 ( 818) -> FUN_140963260");
        println("  opcode 0x0348 ( 840) -> FUN_1409657b0");
        println("  opcode 0x034E ( 846) -> FUN_1409d4e50");
        println("  opcode 0x036A ( 874) -> FUN_140985de0");
        println("  opcode 0x037E ( 894) -> falls through to 0x3C3");
        println("  opcode 0x039A ( 922) -> FUN_140964f60");
        println("  opcode 0x039E ( 926) -> inline byte manipulation");
        println("  opcode 0x03B3 ( 947) -> FUN_140a906c0");
        println("  opcode 0x03C3 ( 963) -> shared with 0x37E");
        println("  opcode 0x03C4 ( 964) -> inline with local_16c");
        println("  opcode 0x03C7 ( 967) -> FUN_140967dc0");
        println("  opcode 0x03DA ( 986) -> FUN_140966430");
        println("  opcode 0x03E0 ( 992) -> FUN_140968030");
        println("  opcode 0x03F4 (1012) -> FUN_1409619c0");
        println("  opcode 0x03FF (1023) -> inline with local_168");
        println("  opcode 0x0409 (1033) -> FUN_140a98590");
        println("  opcode 0x0416 (1046) -> FUN_1409d3340");
        println("  opcode 0x041C (1052) -> FUN_140967770");
        println("  opcode 0x0438 (1080) -> inline byte check");
        println("  opcode 0x043B (1083) -> inline with local_160");
        println("  opcode 0x0479 (1145) -> (last opcode, checked with if)");

        println("\n=== SUMMARY ===");
        println("Dispatcher function: FUN_140955c20 at 0x140955C20");
        println("Opcode field: 16-bit unsigned short at packet_struct + 0x08");
        println("Opcode range: 0x000A to 0x0479 (10 to 1145)");
        println("Jump table: byte index at 0x140957120, dword offsets at 0x1409570C4");
        println("Total unique handled opcodes: ~81 (from decompiled switch cases)");

        println("\n=== DONE ===");
        decomp.dispose();
    }
}
