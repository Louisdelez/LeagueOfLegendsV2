//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class ForceDecompile extends GhidraScript {
    public void run() throws Exception {
        Address base = currentProgram.getImageBase();
        
        // Force create a function at the sendto loop
        // The sendto call is at 0x58ECB5. The loop probably starts much earlier.
        // From the stack: only ntdll above -> this IS the thread entry function
        // Thread functions typically start at an exported or well-aligned address
        
        // Try creating a function at several candidate addresses
        long[] candidates = {
            0x58E800L, 0x58E810L, 0x58E820L, 0x58E830L, 0x58E840L,
            0x58E850L, 0x58E860L, 0x58E870L, 0x58E880L, 0x58E890L,
            0x58E8A0L, 0x58E8B0L, 0x58E8C0L, 0x58E8D0L, 0x58E8E0L,
            0x58E8F0L, 0x58E900L, 0x58E910L, 0x58E920L,
            0x58EA00L, 0x58EA10L, 0x58EA20L,
        };
        
        for (long off : candidates) {
            Address addr = base.add(off);
            try {
                byte[] bytes = new byte[4];
                currentProgram.getMemory().getBytes(addr, bytes);
                // Check for common x64 function prologues
                boolean isPrologue = false;
                if ((bytes[0] & 0xFF) == 0x48 && (bytes[1] & 0xFF) == 0x89) isPrologue = true; // mov [rsp+xx], reg
                if ((bytes[0] & 0xFF) == 0x48 && (bytes[1] & 0xFF) == 0x83 && (bytes[2] & 0xFF) == 0xEC) isPrologue = true; // sub rsp
                if ((bytes[0] & 0xFF) == 0x40 && (bytes[1] & 0xFF) >= 0x50 && (bytes[1] & 0xFF) <= 0x57) isPrologue = true; // push reg
                if ((bytes[0] & 0xFF) == 0x55) isPrologue = true; // push rbp
                if ((bytes[0] & 0xFF) == 0x53) isPrologue = true; // push rbx
                
                if (isPrologue) {
                    println("Prologue at " + addr + ": " + String.format("%02X %02X %02X %02X", bytes[0]&0xFF, bytes[1]&0xFF, bytes[2]&0xFF, bytes[3]&0xFF));
                    
                    // Create function
                    createFunction(addr, "NET_" + Long.toHexString(off));
                    Function f = getFunctionAt(addr);
                    if (f != null) {
                        println("Created function " + f.getName());
                        
                        // Check if it contains the sendto call at 0x58ECB5
                        if (off < 0x58ECBBL && f.getBody().contains(base.add(0x58ECBBL))) {
                            println("*** THIS FUNCTION CONTAINS THE SENDTO CALL! ***");
                            ghidra.app.decompiler.DecompInterface d = new ghidra.app.decompiler.DecompInterface();
                            d.openProgram(currentProgram);
                            ghidra.app.decompiler.DecompileResults r = d.decompileFunction(f, 120, monitor);
                            if (r.decompileCompleted()) {
                                String[] lines = r.getDecompiledFunction().getC().split("\n");
                                for (int i = 0; i < Math.min(lines.length, 300); i++) println(lines[i]);
                            }
                            d.dispose();
                        }
                    }
                }
            } catch (Exception e) {}
        }
        
        println("\n=== DONE ===");
    }
}
