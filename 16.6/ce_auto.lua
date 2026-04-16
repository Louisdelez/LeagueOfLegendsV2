-- Auto-patch CRC check via Cheat Engine kernel driver
dbk_initialize()
openProcess("League of Legends.exe")
sleep(500)

local base = getAddress("League of Legends.exe")
if base == nil or base == 0 then
  print("ERROR: Can't find base")
  local f = io.open("D:/LeagueOfLegendsV2/ce_result.txt", "w")
  f:write("ERROR_NO_BASE\n")
  f:close()
  closeCE()
  return
end

local target = base + 0x572827
local bytes = readBytes(target, 6, true)
if bytes == nil then
  local f = io.open("D:/LeagueOfLegendsV2/ce_result.txt", "w")
  f:write("ERROR_CANT_READ\n")
  f:close()
  closeCE()
  return
end

local cur = string.format("%02X %02X %02X %02X %02X %02X", bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6])

if bytes[1] == 0x90 and bytes[4] == 0xB0 then
  local f = io.open("D:/LeagueOfLegendsV2/ce_result.txt", "w")
  f:write("ALREADY_PATCHED\n")
  f:close()
  closeCE()
  return
end

if bytes[1] ~= 0x44 or bytes[2] ~= 0x3B or bytes[3] ~= 0xE0 then
  local f = io.open("D:/LeagueOfLegendsV2/ce_result.txt", "w")
  f:write("WRONG_BYTES: " .. cur .. "\n")
  f:close()
  closeCE()
  return
end

-- Try auto-assemble (kernel mode)
local script = string.format("[enable]\n%X:\nnop\nnop\nnop\nmov al,1\nnop\n", target)
local ok = autoAssemble(script)

if not ok then
  -- Try writeBytes
  writeBytes(target, 0x90, 0x90, 0x90, 0xB0, 0x01, 0x90)
end

sleep(200)
local after = readBytes(target, 6, true)
local result = string.format("%02X %02X %02X %02X %02X %02X", after[1], after[2], after[3], after[4], after[5], after[6])

local f = io.open("D:/LeagueOfLegendsV2/ce_result.txt", "w")
if after[1] == 0x90 and after[4] == 0xB0 then
  f:write("PATCH_OK\n")
  f:write("Before: " .. cur .. "\n")
  f:write("After:  " .. result .. "\n")
else
  f:write("PATCH_FAILED\n")
  f:write("Before: " .. cur .. "\n")
  f:write("After:  " .. result .. "\n")
end
f:close()
closeCE()
