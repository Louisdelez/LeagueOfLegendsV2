import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
public class FindSSLNew extends GhidraScript {
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        // "SSL_CTX_new" string
        byte[] p = "SSL_CTX_new".getBytes("UTF-8");
        Address addr = mem.findBytes(currentProgram.getMinAddress(), p, null, true, monitor);
        while (addr != null) {
            println("SSL_CTX_new string at: " + addr);
            // Read surrounding bytes for context
            byte[] buf = new byte[32];
            mem.getBytes(addr, buf);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 32; i++) {
                char c = (char)(buf[i] & 0xFF);
                if (c >= 32 && c < 127) sb.append(c); else break;
            }
            println("  Full string: " + sb.toString());
            addr = mem.findBytes(addr.add(1), p, null, true, monitor);
        }
        // Find the function that calls SSL_CTX_new (look at FUN_14072c890 = SSL context init)
        Address ctxInit = currentProgram.getAddressFactory().getAddress("14072c890");
        var fn = currentProgram.getFunctionManager().getFunctionAt(ctxInit);
        if (fn != null) {
            println("FUN_14072c890 (SSL context init) found, size=" + fn.getBody().getNumAddresses());
        }
    }
}
