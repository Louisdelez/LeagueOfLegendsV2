//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class DisasmSendto extends GhidraScript {
    public void run() throws Exception {
        Address base = currentProgram.getImageBase();
        // Disassemble around the sendto call at offset 0x58ECBB
        Address addr = base.add(0x58EC80L); // Start a bit before
        println("=== Assembly around sendto call ===");
        for (int i = 0; i < 30; i++) {
            Instruction inst = currentProgram.getListing().getInstructionAt(addr);
            if (inst != null) {
                String marker = addr.equals(base.add(0x58ECBBL)) ? " <-- SENDTO CALL" : "";
                println(addr + ": " + inst + marker);
                addr = addr.add(inst.getLength());
            } else {
                // Try to read bytes
                byte b = currentProgram.getMemory().getByte(addr);
                println(addr + ": DB 0x" + String.format("%02X", b & 0xFF));
                addr = addr.add(1);
            }
        }

        // Also find: what function REALLY contains 0x58ECBB?
        println("\n=== Function containing sendto call ===");
        // Disassemble at the call site first to create instructions
        currentProgram.getListing().clearCodeUnits(base.add(0x58EC80L), base.add(0x58ED00L), false);
        disassemble(base.add(0x58EC80L));
        
        Function f = getFunctionContaining(base.add(0x58ECBBL));
        if (f != null) {
            println("Function: " + f.getName() + " at " + f.getEntryPoint());
        } else {
            println("Still no function. Creating one...");
            // Search backwards for function start pattern (push rbp or sub rsp)
            for (long off = 0; off < 0x500; off++) {
                Address tryAddr = base.add(0x58ECBBL - off);
                byte[] bytes = new byte[4];
                currentProgram.getMemory().getBytes(tryAddr, bytes);
                // Common function prologues:
                // 48 89 5C 24 = mov [rsp+xx], rbx (save register)  
                // 48 83 EC = sub rsp, xx
                // 40 53 = push rbx (with REX prefix)
                if ((bytes[0] & 0xFF) == 0x48 && (bytes[1] & 0xFF) == 0x83 && (bytes[2] & 0xFF) == 0xEC) {
                    println("Possible function start at " + tryAddr + " (sub rsp, 0x" + String.format("%02X", bytes[3] & 0xFF) + ")");
                }
                if ((bytes[0] & 0xFF) == 0x48 && (bytes[1] & 0xFF) == 0x89 && (bytes[2] & 0xFF) == 0x5C) {
                    println("Possible function start at " + tryAddr + " (mov [rsp+xx], rbx)");
                }
            }
        }
        println("=== DONE ===");
    }
}
