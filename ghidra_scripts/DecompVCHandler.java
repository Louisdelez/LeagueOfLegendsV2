import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;

public class DecompVCHandler extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // 1. Decompile FUN_140588f70 handler dispatch path
        // After CRC check passes, it calls: (**(code**)(*plVar15 + 0x28))(plVar15, &local_c8)
        // plVar15 = *(longlong**)(param_1 + 0x20) or (param_1 + 8)
        // We need to find what function is at the vtable +0x28 slot

        // 2. First, let's look at the virtual call site in FUN_140588f70
        // The call is at some address inside 588f70. Let's find it.
        println("=== Looking for virtual call in FUN_140588f70 ===");
        Address f588start = currentProgram.getAddressFactory().getAddress("140588f70");
        // Scan for CALL instructions in the function (588f70 to ~589300)
        for (long addr = 0x140588f70L; addr < 0x140589300L; ) {
            Address a = currentProgram.getAddressFactory().getAddress(String.format("%x", addr));
            Instruction inst = currentProgram.getListing().getInstructionAt(a);
            if (inst != null) {
                String s = inst.toString();
                if (s.contains("CALL") && (s.contains("RAX") || s.contains("[R"))) {
                    println(String.format("  %s: %s", a, inst));
                }
                addr += inst.getLength();
            } else {
                addr++;
            }
        }

        // 3. Decompile the ENet command dispatcher
        // In ENet, after receiving and validating a packet, commands are dispatched
        // based on the command type. VERIFY_CONNECT = 3.
        // The handler is likely called from FUN_14058e370 (recv_handler) or similar
        
        // Let's decompile FUN_14058e370 which we saw in ghidra_recv_handler.txt
        println("\n=== Decompiling FUN_14058e370 (recv handler) ===");
        Address rh = currentProgram.getAddressFactory().getAddress("14058e370");
        Function fRH = currentProgram.getFunctionManager().getFunctionContaining(rh);
        if (fRH != null) {
            DecompileResults result = decomp.decompileFunction(fRH, 180, monitor);
            if (result.decompileCompleted()) {
                for (String line : result.getDecompiledFunction().getC().split("\n"))
                    println(line);
            }
        } else {
            println("No function at 14058e370");
        }

        // 4. Look for the command dispatch switch/if-chain
        // Search for CMP with 3 (VERIFY_CONNECT command type) near the handler area
        println("\n=== Searching for cmd==3 checks (VERIFY_CONNECT dispatch) ===");
        // Check in the broad area 0x5880000-0x5900000
        for (long addr = 0x140588000L; addr < 0x140590000L; ) {
            Address a = currentProgram.getAddressFactory().getAddress(String.format("%x", addr));
            Instruction inst = currentProgram.getListing().getInstructionAt(a);
            if (inst != null) {
                String s = inst.toString();
                // Look for CMP reg, 0x3 followed by JZ (switch on command type 3)
                if (s.contains("CMP") && s.contains(",0x3") && !s.contains("0x30") && !s.contains("0x3e") && !s.contains("0x3f")) {
                    // Check next instruction for conditional jump
                    Address next = a.add(inst.getLength());
                    Instruction nextInst = currentProgram.getListing().getInstructionAt(next);
                    if (nextInst != null && (nextInst.toString().contains("JZ") || nextInst.toString().contains("JNZ"))) {
                        println(String.format("  %s: %s → %s", a, inst, nextInst));
                    }
                }
                addr += inst.getLength();
            } else {
                addr++;
            }
        }

        // 5. Decompile FUN_14058a4f0 which processes reliable commands
        // This contains the VERIFY_CONNECT processing for cmd type 3
        println("\n=== Decompiling area around command handlers ===");
        // Try FUN_14057af90 (caller of FUN_140589fc0 per recv_caller.txt)
        Address af90 = currentProgram.getAddressFactory().getAddress("14057af90");
        Function fAF90 = currentProgram.getFunctionManager().getFunctionContaining(af90);
        if (fAF90 != null) {
            println("Function at " + fAF90.getEntryPoint() + " " + fAF90.getName() + " size=" + fAF90.getBody().getNumAddresses());
            DecompileResults result = decomp.decompileFunction(fAF90, 180, monitor);
            if (result.decompileCompleted()) {
                String code = result.getDecompiledFunction().getC();
                String[] lines = code.split("\n");
                println("Lines: " + lines.length);
                // Print first 200 lines
                for (int i = 0; i < Math.min(200, lines.length); i++)
                    println(lines[i]);
            }
        }

        println("\n=== DONE ===");
        decomp.dispose();
    }
}
