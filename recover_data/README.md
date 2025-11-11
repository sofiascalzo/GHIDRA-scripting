# GHIDRA Recover Data

**Short description**

Custom Ghidra script to help reverse code for CTFs and gather data efficiently with a few clicks.

**What it does (concise)**

- Scans program symbols and keeps only `s_...` (strings), `LAB_...` (labels) and `DAT_...` (data) entries.
- For each `DAT_...`, reads raw bytes from its memory block up to a safety limit (default 1024 bytes).
- Produces an alphabetically sorted list of tuples with both raw and hex representations.

**Output format**

Each printed tuple follows this format:

```
(name, raw_bytes_string, function_or_None, address_string, hex_string)
```

- `name`: symbol name (e.g. `DAT_00104010`, `s_/flag_00102024`, `LAB_00101501`).
- `raw_bytes_string`: raw bytes as an *undecoded* string (allows non-ASCII values to remain visible in the output).
- `function_or_None`: the function name containing the address, or `None`.
- `address_string`: the address as a string (e.g. `00104010`).
- `hex_string`: hex representation of the same bytes (useful for manual inspection).

**Usage**

1. Save the script as `GHIDRA_recover_data.py` in your Ghidra scripts folder.
2. Open the target program in Ghidra and run the script from Script Manager.
3. Inspect the printed tuples in the script output console or redirect output to a file.

**Notes & choices**

- The script intentionally excludes symbols starting with `PTR_` and `__DT_`.
- `MAX_BYTES` is a safety cap to avoid huge dumps; change it if you need to read larger blocks.
- Raw bytes are built using `chr()` for compatibility with Jython (Ghidra's Python 2).

**Disclaimer (English)**

This tool is provided for **educational purposes only** — to practice Ghidra scripting and binary analysis on programs you are authorized to analyze. Do not use it for any unauthorized access, reverse engineering of proprietary software without permission, or other malicious activity. The author and contributors are not responsible for misuse.

---

*Author*: Sofia Scalzo

*License*: Add your preferred license when publishing to GitHub.