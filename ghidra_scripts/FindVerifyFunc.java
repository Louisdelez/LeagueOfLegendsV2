import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
public class FindVerifyFunc extends GhidraScript {
    public void run() throws Exception {
        // The "certificate verify failed" at 141a7cb48 is likely in the BoringSSL error table
        // But "tls_process_server_certificate" strings are in the error string area
        // Let's find SSL_CTX_set_verify or the verify callback setter
        Memory mem = currentProgram.getMemory();
        
        // Search for "ssl_verify_cert_chain" - the core cert verification function
        byte[] p = "x509_verify_cert".getBytes("UTF-8");
        Address addr = mem.findBytes(currentProgram.getMinAddress(), p, null, true, monitor);
        while (addr != null) {
            println("x509_verify_cert string at: " + addr);
            addr = mem.findBytes(addr.add(1), p, null, true, monitor);
        }

        // Find SSL_VERIFY_NONE value (0) and SSL_VERIFY_PEER (1) patterns
        // In BoringSSL, the verify mode is checked with: if (ssl->verify_mode != SSL_VERIFY_NONE)
        
        // Find "custom_verify" - BoringSSL's custom verify callback
        p = "custom_verify".getBytes("UTF-8");
        addr = mem.findBytes(currentProgram.getMinAddress(), p, null, true, monitor);
        while (addr != null) {
            println("custom_verify string at: " + addr);
            addr = mem.findBytes(addr.add(1), p, null, true, monitor);
        }
        
        // Search for the actual SSL_CTX struct by looking for the method table pattern
        // In BoringSSL, SSL_CTX has ssl_ctx_st with a 'method' pointer at offset 0
        // SSL_CTX_new allocates and initializes it
        // Let's find "SSL_CTX_set_verify" string
        p = "SSL_CTX_set".getBytes("UTF-8");
        addr = mem.findBytes(currentProgram.getMinAddress(), p, null, true, monitor);
        while (addr != null) {
            println("SSL_CTX_set at: " + addr);
            addr = mem.findBytes(addr.add(1), p, null, true, monitor);
        }
    }
}
