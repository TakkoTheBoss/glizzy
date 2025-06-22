# GLIZZY — BLE GATT Handle Fuzzer

![GLIZZY Icon PNG](glizzy.jpg "Glizzy Gobbler")

GLIZZY is a terminal-based tool for fuzzing Bluetooth Low Energy (BLE) GATT characteristic handles.  
It can probe writeable lengths, perform repeated runs, inject random or static hex payloads, and immediately read back values. Output is color-coded and concise.

---

## Intended Use

It's recommended to use GLIZZY after the running services on the target bluetooth low energy (BTLE/BLE) target device are discovered. Running in incremental mode and omitting the `-r` random flag allows the user to discover how many characters the handle (or service) will allow.

![ GLIZZY Run ](glizzyrun.png "GLIZZY Run")

![ GLIZZY Run 2 ](glizzyrun2.png "GLIZZY Run 2")

Once these are identified, then the `-r` random mode with `-n` number of fuzz runs can be enabled, to drill down on those service with the accepted input size.

---

## Installation

1. Ensure you have **Python 3** and `gatttool` installed (from the BlueZ package).
2. Clone or download **`ble_fuzzer.py`** into your working directory.
3. Make sure it’s executable:
   ```bash
   chmod +x ble_fuzzer.py
   ```

---

## Usage

```bash
sudo python3 ble_fuzzer.py <MAC> [options]
```

- You **must** run as root (or with `sudo`) to use `gatttool`.

### Positional Arguments

| Name  | Description                             |
|-------|-----------------------------------------|
| `MAC` | BLE device MAC address (e.g. `9C:F1:D4:40:08:13`) |

### Options

| Flag                    | Shorthand | Arg        | Default  | Description                                                                    |
|-------------------------|-----------|------------|----------|--------------------------------------------------------------------------------|
| `--services`            | `-s`      | hex range… | —        | One or more GATT service handle ranges. e.g. `0x1-0x9 0x000d-0x000f`            |
| `--handles`             | `-H`      | hex/hex-range… | —     | One or more explicit handles. e.g. `0x0003 0x0007-0x000a`                        |
| `--uuid`                | `-u`      | UUID       | —        | Filter discovered services by UUID prefix (e.g. `00005001`)                     |
| `--chars`               | `-c`      | number     | `10`     | Maximum payload length (in hex-nibbles) for incremental mode (1…N)              |
| `--runs`                | `-n`      | number     | —        | Static-length mode: perform this many writes all at exactly `--chars` length    |
| `--addr-type`           | `-a`      | `public\|random` | `public` | LE address type to use when connecting                                          |
| `--random`              | `-r`      | (flag)     | off      | Use random hex payloads instead of all-zero payloads                            |
| `-h, --help`            | —         | —          | —        | Show help message                                                               |

---

## Modes of Operation

### 1. Incremental Mode (Default)
Probes each handle from length 1 up to `--chars`.

```bash
sudo python3 ble_fuzzer.py 9C:F1:D4:40:08:13   -s 0x000d-0x000d   -c 5
```

**Output:**
```
==> DISCOVER SERVICES
==> FUZZING HANDLES
Service handles d-d (UUID: manual)

✖ 0x000d len=1   input=0x0 -> Invalid value
? 0x000d len=2   input=0x00 -> Characteristic Write Request failed: Attribute value length is invalid
? 0x000d len=3   input=0x000 -> Characteristic Write Request failed: Attribute value length is invalid
✔ 0x000d len=4   input=0x0000 -> OK readback=Characteristic value/descriptor: 00 00
✔ 0x000d len=5   input=0x00000 -> OK readback=Characteristic value/descriptor: 00 00

==> SUMMARY
0x000d: max 5 bytes, fail at None
```

### 2. Static-Length Mode
Repeat exactly `--chars`-length writes for `--runs` iterations:

```bash
sudo python3 ble_fuzzer.py 9C:F1:D4:40:08:13   -s 0x000d-0x000d   -c 8   -n 5
```

- Sends five writes, each with an 8-hex-nibble payload.
- Use `-r` to randomize each payload.

---

## Color Legend

- **✔** (green) – Write succeeded & read-back shown  
- **✖** (red) – Hard failure (non-zero exit, unexpected error)  
- **?** (yellow) – Soft failure (“Attribute value length is invalid”)  
- **Service handles…** (cyan) – Section headers  
- **Summary** (magenta) – Result summary  

---

## Examples

1. **Fuzz a single handle**  
   ```bash
   sudo python3 ble_fuzzer.py 9C:F1:D4:40:08:13      -H 0x000d      -c 10      -r
   ```

2. **Filter by service UUID**  
   ```bash
   sudo python3 ble_fuzzer.py 9C:F1:D4:40:08:13      -u 00005001      -c 6
   ```

3. **Full default discovery + incremental fuzz**  
   ```bash
   sudo python3 ble_fuzzer.py 9C:F1:D4:40:08:13
   ```


