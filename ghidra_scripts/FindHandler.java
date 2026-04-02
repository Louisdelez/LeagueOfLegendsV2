import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;

public class FindHandler extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // Disassemble around the CALL [RAX+0x28] at 140589276 to see what RAX is
        println("=== Instructions before CALL [RAX+0x28] at 140589276 ===");
        for (long a = 0x140589250L; a < 0x140589290L; ) {
            Address addr = currentProgram.getAddressFactory().getAddress(String.format("%x", a));
            Instruction inst = currentProgram.getListing().getInstructionAt(addr);
            if (inst != null) {
                println(String.format("  %s: %s", addr, inst));
                a += inst.getLength();
            } else a++;
        }

        // The virtual call table is from an object. Let's find what class it is.
        // Look for vtable references - search for the address that gets loaded into RAX
        // before the call. Typically: MOV RAX, [RCX] or MOV RAX, [plVar15]

        // Also: search for functions that could be at vtable+0x28
        // In ENet-like code, the handler for received commands would be something like
        // "enet_host_service_packet" or "protocol_handle_incoming_commands"
        // Let's search for functions near the range that handle ENet commands

        // Decompile FUN_14058e370 fully (recv_handler we saw earlier)  
        println("\n=== FUN_14058e370 decompilation ===");
        Function f = currentProgram.getFunctionManager().getFunctionAt(
            currentProgram.getAddressFactory().getAddress("14058e370"));
        if (f != null) {
            DecompileResults r = decomp.decompileFunction(f, 180, monitor);
            if (r.decompileCompleted()) {
                String code = r.getDecompiledFunction().getC();
                for (String line : code.split("\n")) println(line);
            }
        }

        // Also find the function at the address after the handler returns
        // The next instruction after CALL [RAX+0x28] continues at 140589278
        // Let's see what else is in FUN_140588f70

        println("\n=== Key instructions in FUN_140588f70 handler dispatch area ===");
        for (long a = 0x140589260L; a < 0x1405892B0L; ) {
            Address addr = currentProgram.getAddressFactory().getAddress(String.format("%x", a));
            Instruction inst = currentProgram.getListing().getInstructionAt(addr);
            if (inst != null) {
                println(String.format("  %s: %s", addr, inst));
                a += inst.getLength();
            } else a++;
        }

        println("\n=== DONE ===");
        decomp.dispose();
    }
}
