-- CRC Bypass v2 - Force kernel driver usage
-- Diagnostics + multiple kernel write methods

print("=== CRC Bypass v2 ===")
print("")

-- Step 1: Check kernel driver status
print("[1] Initializing kernel driver...")
local ok = dbk_initialize()
print("    dbk_initialize() = " .. tostring(ok))

-- Check if driver is actually loaded
local driverLoaded = isDriverLoaded and isDriverLoaded() or "unknown"
print("    Driver loaded: " .. tostring(driverLoaded))

-- Step 2: Get base
local base = getAddress("League of Legends.exe")
if base == nil or base == 0 then
  print("ERROR: Can't find League of Legends.exe!")
  return
end
print(string.format("[2] Base: 0x%X", base))

local target = base + 0x572827
print(string.format("    Target: 0x%X", target))

-- Step 3: Read current bytes (try kernel read)
print("[3] Reading current bytes...")
local bytes = readBytes(target, 6, true)
if bytes == nil then
  print("    readBytes failed, trying dbk_readProcessMemory...")
  -- try raw kernel read
  local pid = getOpenedProcessID()
  print("    PID: " .. tostring(pid))
  bytes = readBytes(target, 6, true)
end

if bytes == nil then
  print("ERROR: Cannot read target address at all!")
  return
end

print(string.format("    Current: %02X %02X %02X %02X %02X %02X",
    bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6]))

if bytes[1] == 0x90 and bytes[4] == 0xB0 then
  print("Already patched!")
  return
end

if bytes[1] ~= 0x44 or bytes[2] ~= 0x3B or bytes[3] ~= 0xE0 then
  print("ERROR: Unexpected bytes! Expected 44 3B E0 0F 94 C0")
  return
end

print("[4] Bytes verified. Trying all write methods...")
print("")

-- Patch bytes
local patch = {0x90, 0x90, 0x90, 0xB0, 0x01, 0x90}

-- Method 1: openProcess with kernel privileges then writeBytes
print("--- Method 1: writeBytes (uses kernel if settings enabled) ---")
writeBytes(target, patch)
local after1 = readBytes(target, 6, true)
print(string.format("    After: %02X %02X %02X %02X %02X %02X",
    after1[1], after1[2], after1[3], after1[4], after1[5], after1[6]))
if after1[1] == 0x90 then
  print("    >>> METHOD 1 SUCCESS!")
  goto done
end
print("    Method 1 failed")
print("")

-- Method 2: dbk_writesProcessMemory (explicit kernel driver write)
print("--- Method 2: dbk_writesProcessMemory ---")
do
  local pid = getOpenedProcessID()
  print("    PID: " .. tostring(pid))

  if dbk_writesProcessMemory then
    -- Write byte by byte
    for i = 0, 5 do
      dbk_writesProcessMemory(pid, target + i, string.char(patch[i+1]), 1)
    end
    local after2 = readBytes(target, 6, true)
    print(string.format("    After: %02X %02X %02X %02X %02X %02X",
        after2[1], after2[2], after2[3], after2[4], after2[5], after2[6]))
    if after2[1] == 0x90 then
      print("    >>> METHOD 2 SUCCESS!")
      goto done
    end
    print("    Method 2 failed")
  else
    print("    dbk_writesProcessMemory not available!")
    print("    Kernel driver is NOT loaded properly.")
  end
end
print("")

-- Method 3: writeProcessMemoryStealthily (if available in newer CE)
print("--- Method 3: autoAssemble with alloc near ---")
do
  local script = string.format([[
[enable]
%X:
db 90 90 90 B0 01 90
]], target)
  local ok3, err3 = autoAssemble(script)
  print("    autoAssemble result: " .. tostring(ok3) .. " err: " .. tostring(err3))
  local after3 = readBytes(target, 6, true)
  print(string.format("    After: %02X %02X %02X %02X %02X %02X",
      after3[1], after3[2], after3[3], after3[4], after3[5], after3[6]))
  if after3[1] == 0x90 then
    print("    >>> METHOD 3 SUCCESS!")
    goto done
  end
  print("    Method 3 failed")
end
print("")

-- Method 4: VirtualProtectEx + write (ring3 but worth trying from CE context)
print("--- Method 4: unprotect + write ---")
do
  local oldProtect = 0
  -- CE's writeBytes should handle VirtualProtect internally,
  -- but let's try explicit unprotect
  if virtualProtectEx then
    local ok4 = virtualProtectEx(getOpenedProcessID(), target, 6, 0x40) -- PAGE_EXECUTE_READWRITE
    print("    VirtualProtectEx: " .. tostring(ok4))
  end
  writeBytes(target, patch)
  local after4 = readBytes(target, 6, true)
  print(string.format("    After: %02X %02X %02X %02X %02X %02X",
      after4[1], after4[2], after4[3], after4[4], after4[5], after4[6]))
  if after4[1] == 0x90 then
    print("    >>> METHOD 4 SUCCESS!")
    goto done
  end
  print("    Method 4 failed")
end
print("")

print("=== ALL METHODS FAILED ===")
print("")
print("Diagnostics:")
print("  - Is CE running as Administrator? (required)")
print("  - Settings > Extra > 'Use kernel mode readprocessmemory': checked?")
print("  - Settings > Extra > 'Use kernel mode writeprocessmemory': checked?")
print("  - After checking those boxes, did you CLOSE and RE-OPEN CE?")
print("  - Vulnerable Driver Blocklist disabled in registry? (check done)")
print("")
print("If kernel options are GREYED OUT, the driver failed to load.")
print("Try: Help > Load driver > Load kernel driver")
do return end

::done::
print("")
print("╔════════════════════════════════════════╗")
print("║   CRC CHECK PATCHED SUCCESSFULLY!      ║")
print("╚════════════════════════════════════════╝")
print("")
print("Now restart the server and client to test!")
