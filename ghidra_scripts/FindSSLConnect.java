import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
public class FindSSLConnect extends GhidraScript {
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        // Search for "tls_process_server_certificate" string
        byte[] p1 = "tls_process_server".getBytes("UTF-8");
        Address addr = mem.findBytes(currentProgram.getMinAddress(), p1, null, true, monitor);
        while (addr != null) {
            println("TLS string at: " + addr);
            addr = mem.findBytes(addr.add(1), p1, null, true, monitor);
        }
        // Search for "SSL_connect" string
        byte[] p2 = "SSL_connect".getBytes("UTF-8");
        addr = mem.findBytes(currentProgram.getMinAddress(), p2, null, true, monitor);
        while (addr != null) {
            println("SSL_connect string at: " + addr);
            addr = mem.findBytes(addr.add(1), p2, null, true, monitor);
        }
        // Search for "certificate verify failed"
        byte[] p3 = "certificate verify".getBytes("UTF-8");
        addr = mem.findBytes(currentProgram.getMinAddress(), p3, null, true, monitor);
        while (addr != null) {
            println("cert verify string at: " + addr);
            addr = mem.findBytes(addr.add(1), p3, null, true, monitor);
        }
    }
}
