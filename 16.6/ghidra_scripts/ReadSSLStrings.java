import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
public class ReadSSLStrings extends GhidraScript {
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        // Read the strings at SSL_CTX_set locations
        long[] addrs = {0x141a80f40L, 0x141a80f58L, 0x141a80f70L, 0x141a80f90L, 0x141a80fb8L, 0x141a80fd8L, 0x141a80ff0L};
        for (long a : addrs) {
            Address addr = currentProgram.getAddressFactory().getAddress(Long.toHexString(a));
            byte[] buf = new byte[64];
            mem.getBytes(addr, buf);
            String s = new String(buf, "UTF-8");
            int end = s.indexOf('\0');
            if (end > 0) s = s.substring(0, end);
            println(String.format("  0x%X: %s", a, s));
        }
    }
}
