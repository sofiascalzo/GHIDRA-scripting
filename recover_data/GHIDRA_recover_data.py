#@author Sofia Scalzo
#@category CTF/Utilities
#@description Recover and dump string, label and DAT symbols (including raw bytes) from stripped binaries. Outputs tuples: (name, raw_bytes_string, function_or_None, address_string, hex_string)

from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.mem import MemoryAccessException

MAX_BYTES = 1024  # safety limit: max bytes to read from each DAT block

symbol_table = currentProgram.getSymbolTable()
symbols = symbol_table.getAllSymbols(True)

results = []

for sym in symbols:
    name = sym.getName()

    # keep only strings, labels, or DAT symbols, remove PTR_ and __DT_ symbols
    if not (name.startswith("s_") or name.startswith("LAB_") or name.startswith("DAT_")):
        continue

    addr = sym.getAddress()
    func = getFunctionContaining(addr)
    func_name = func.getName() if func else None

    raw_bytes_str = ''
    hex_bytes = ''

    if name.startswith("DAT_"):
        mem = currentProgram.getMemory()
        block = mem.getBlock(addr)
        if block is not None:
            block_end = block.getEnd()
            bytes_list = []
            cur_addr = addr
            while cur_addr.compareTo(block_end) <= 0 and len(bytes_list) < MAX_BYTES:
                try:
                    b = mem.getByte(cur_addr) & 0xFF
                except MemoryAccessException:
                    break
                bytes_list.append(b)
                cur_addr = cur_addr.add(1)
            raw_bytes_str = ''.join([chr(b) for b in bytes_list])
            hex_bytes = ''.join("{:02x}".format(b) for b in bytes_list)

    results.append((name, raw_bytes_str, func_name, str(addr), hex_bytes))

# sort alphabetically by name
results.sort(key=lambda x: x[0].lower())

# print tuples
for t in results:
    print(t)