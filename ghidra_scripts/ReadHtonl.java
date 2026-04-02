import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
public class ReadHtonl extends GhidraScript {
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        Address dat = currentProgram.getAddressFactory().getAddress("1418dfd10");
        long ptr = mem.getLong(dat);
        println("DAT_1418dfd10 = 0x" + Long.toHexString(ptr));
        // Check if it points to a known function
        Address fn = currentProgram.getAddressFactory().getAddress(Long.toHexString(ptr));
        var func = currentProgram.getFunctionManager().getFunctionAt(fn);
        if (func != null) {
            println("Points to function: " + func.getName() + " at " + fn);
        } else {
            println("Points to address: " + fn + " (not a function)");
        }
        // Also read first few bytes at that address
        byte[] bytes = new byte[16];
        mem.getBytes(fn, bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02X ", b & 0xFF));
        println("Bytes at target: " + sb.toString());
    }
}
