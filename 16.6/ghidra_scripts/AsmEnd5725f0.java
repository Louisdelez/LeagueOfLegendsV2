import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;
public class AsmEnd5725f0 extends GhidraScript {
    public void run() throws Exception {
        Address addr = currentProgram.getAddressFactory().getAddress("1405725f0");
        Function f = currentProgram.getFunctionManager().getFunctionAt(addr);
        println("=== END OF FUN_1405725f0 (last 30 instructions) ===");
        // Find the end address
        long endOff = f.getEntryPoint().getOffset() + f.getBody().getNumAddresses();
        // Start from near the end
        Address startAsm = currentProgram.getAddressFactory().getAddress(
            String.format("%x", endOff - 80));
        Instruction inst = currentProgram.getListing().getInstructionAfter(startAsm);
        int count = 0;
        while (inst != null && count < 40) {
            long off = inst.getAddress().getOffset();
            if (off >= endOff) break;
            println(String.format("  %s: %s", inst.getAddress(), inst));
            inst = inst.getNext();
            count++;
        }
    }
}
