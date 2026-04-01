import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;
public class AsmCFBRead extends GhidraScript {
    public void run() throws Exception {
        // FUN_1410f41e0 starts at 1410f41e0
        // Mode 2 code should be around offset +0x60 to +0xC0
        Address start = currentProgram.getAddressFactory().getAddress("1410f4240");
        Instruction inst = currentProgram.getListing().getInstructionAfter(start);
        println("=== FUN_1410f41e0 mode 2 assembly ===");
        int count = 0;
        while (inst != null && count < 40) {
            println(inst.getAddress() + ": " + inst);
            inst = inst.getNext();
            count++;
        }
    }
}
