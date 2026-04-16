import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
public class FindTimeoutXref extends GhidraScript {
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        // The string "Timeout waiting to connect to: " is at 0x141952c1b
        // Search .text for LEA instructions that reference nearby
        // RIP-relative: LEA reg, [RIP + disp32]
        // disp32 = target - (instr_addr + instr_len)
        // Typical LEA is 7 bytes: 48 8D xx xx xx xx xx (REX.W + LEA + modrm + disp32)
        
        long targetAddr = 0x141952c1bL;
        
        // Search a wide range of .text for references
        // For each instruction in .text, check if target = instr + len + disp32
        // Brute force: search for 4-byte patterns that could be disp32
        Address textStart = currentProgram.getAddressFactory().getAddress("140001000");
        
        // For a 7-byte LEA at address X: disp32 = target - (X + 7)
        // So disp32 = 0x141952c1b - X - 7
        // We search for this disp32 as 4 LE bytes following a LEA opcode
        
        // Alternative: search for the string address as an absolute 8-byte value
        // (used with MOV reg, imm64)
        byte[] absPattern = new byte[8];
        for (int i = 0; i < 8; i++) absPattern[i] = (byte)((targetAddr >> (i*8)) & 0xFF);
        Address found = mem.findBytes(textStart, absPattern, null, true, monitor);
        if (found != null) {
            println("Absolute ref to timeout string at: " + found);
        }
        
        // Search for "Timeout" as a separate string that might be concatenated
        byte[] p = "Timeout".getBytes("UTF-8");
        Address addr = mem.findBytes(currentProgram.getMinAddress(), p, null, true, monitor);
        int count = 0;
        while (addr != null && count < 20) {
            var refs = getReferencesTo(addr);
            if (refs.length > 0) {
                var block = mem.getBlock(addr);
                println("\"Timeout\" at " + addr + " (" + block.getName() + ") " + refs.length + " xrefs");
                for (var ref : refs) {
                    Function fn = getFunctionContaining(ref.getFromAddress());
                    println("  " + ref.getFromAddress() + " in " + (fn != null ? fn.getName() + " at " + fn.getEntryPoint() : "unknown"));
                }
            }
            addr = mem.findBytes(addr.add(1), p, null, true, monitor);
            count++;
        }
    }
}
