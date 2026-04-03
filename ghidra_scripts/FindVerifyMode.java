import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
public class FindVerifyMode extends GhidraScript {
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        // Search for "verify_mode" and "SSL_set_verify" strings
        String[] patterns = {"verify_mode", "SSL_set_verify", "set_verify", "custom_verify_callback", "VERIFY_PEER"};
        for (String pat : patterns) {
            byte[] p = pat.getBytes("UTF-8");
            Address addr = mem.findBytes(currentProgram.getMinAddress(), p, null, true, monitor);
            while (addr != null) {
                println(pat + " at: " + addr);
                addr = mem.findBytes(addr.add(1), p, null, true, monitor);
            }
        }
    }
}
