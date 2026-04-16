// Frida script to hook OpenSSL EVP functions in LoLPrivate.exe
// This captures the Blowfish mode, key, and IV used for encryption

// Find the Blowfish P-box pattern in memory to locate the EVP_bf_cbc function
var pboxPattern = [0x88, 0x6A, 0x3F, 0x24, 0xD3, 0x08, 0xA3, 0x85, 0x2E, 0x8A, 0x19, 0x13];

// Search for "BF-CBC" string to find the cipher type
var bfCbcAddr = null;
var mainModule = Process.enumerateModules()[0]; // LoLPrivate.exe
console.log("[*] Main module: " + mainModule.name + " base=" + mainModule.base + " size=" + mainModule.size);

// Scan for "BF-CBC" string
var bfPattern = "42 46 2D 43 42 43"; // "BF-CBC" in hex
Memory.scan(mainModule.base, mainModule.size, bfPattern, {
    onMatch: function(address, size) {
        console.log("[*] Found 'BF-CBC' string at " + address);
        bfCbcAddr = address;
    },
    onComplete: function() {
        if (bfCbcAddr) {
            console.log("[+] BF-CBC located. Now scanning for EVP functions...");
        }
    }
});

// Hook WSASendTo to capture outgoing packets
var ws2 = Module.findBaseAddress("ws2_32.dll");
if (ws2) {
    var WSASendTo = Module.findExportByName("ws2_32.dll", "WSASendTo");
    if (WSASendTo) {
        Interceptor.attach(WSASendTo, {
            onEnter: function(args) {
                var bufs = args[1]; // LPWSABUF
                var cnt = args[2].toInt32();
                for (var i = 0; i < cnt; i++) {
                    var bufLen = bufs.add(i * 16).readU32();
                    var bufPtr = bufs.add(i * 16 + 8).readPointer();
                    if (bufLen > 0) {
                        console.log("[WSASendTo] " + bufLen + " bytes");
                        console.log("  " + hexdump(bufPtr, { length: Math.min(bufLen, 48) }));
                    }
                }
            }
        });
        console.log("[+] Hooked WSASendTo at " + WSASendTo);
    }

    var WSARecvFrom = Module.findExportByName("ws2_32.dll", "WSARecvFrom");
    if (WSARecvFrom) {
        Interceptor.attach(WSARecvFrom, {
            onLeave: function(retval) {
                if (retval.toInt32() === 0) {
                    // Data received - we can inspect the buffers
                    // But we need to save the args from onEnter
                }
            }
        });
        console.log("[+] Hooked WSARecvFrom at " + WSARecvFrom);
    }
}

// Now the key part: find and hook EVP_CipherInit_ex
// In OpenSSL, EVP_CipherInit_ex signature:
//   int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
//                         ENGINE *impl, const unsigned char *key,
//                         const unsigned char *iv, int enc);
//
// We need to find this function. It's compiled into LoLPrivate.exe.
// We can find it by searching for code that references the "BF-CBC" string.

// Alternative: scan for the P-box initialization code pattern
// BF_set_key writes to a BF_KEY structure: it XORs the key with P-box values
// then encrypts pairs of zeros to derive the new P/S box values

// Let's try scanning for known OpenSSL function patterns
// EVP_CipherInit_ex typically starts with: push rbp; mov rbp, rsp; ...
// and references the cipher method table

// Actually, the simplest approach: scan ALL exported-like functions in the module
// for ones that take 6 arguments (matching EVP_CipherInit_ex signature)
// and reference the BF-CBC address

// For now, let's just monitor memory writes to find when Blowfish key is set
// We know the P-box location in the exe at offset 0x19ECDC0
var pboxOffset1 = 0x19ECDC0;
var pboxAddr1 = mainModule.base.add(pboxOffset1);
console.log("[*] Static P-box at " + pboxAddr1);

// Read current P-box values
var currentPbox = pboxAddr1.readByteArray(72);
console.log("[*] Current P-box (first 16 bytes): " + hexdump(pboxAddr1, {length: 16}));

// Set up a memory access watcher on the P-box area
// This will fire when BF_set_key modifies the P-box
MemoryAccessMonitor.enable([{
    base: pboxAddr1,
    size: 72
}], {
    onAccess: function(details) {
        console.log("[!!!] P-BOX WRITE at " + details.address + " from " + details.from);
        console.log("  Operation: " + details.operation);
        console.log("  Caller: " + details.from);

        // Get the call stack
        var bt = Thread.backtrace(details.from, Backtracer.ACCURATE);
        console.log("  Backtrace:");
        for (var i = 0; i < bt.length && i < 10; i++) {
            var addr = bt[i];
            var mod = Process.findModuleByAddress(addr);
            var modName = mod ? mod.name : "???";
            var offset = mod ? addr.sub(mod.base) : "???";
            console.log("    " + addr + " " + modName + "+0x" + offset);
        }
    }
});
console.log("[+] Memory monitor on P-box enabled");

console.log("\n[*] Frida hooks active. Waiting for activity...");
