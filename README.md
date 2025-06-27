
# GLIZZY — BLE GATT Handle Fuzzer

GLIZZY is a terminal-based Python tool for fuzzing Bluetooth Low Energy (BLE) GATT characteristic handles.

It can:
- Discover primary services and characteristics
- Fuzz writeable handles with random or static hex payloads
- Log results and read back values
- Run in read-only mode or via an interactive TUI (if `curses` is installed)

Color-coded output makes it easy to interpret results at a glance.

---

## Intended Use

Use GLIZZY after identifying the target BLE device. It is ideal for:
- Validating max accepted payload lengths
- Discovering valid GATT handles
- Triggering device-specific behaviors based on writes
- Observing potential crash or error conditions from malformed input

Start with incremental mode (no `-r`) to probe lengths safely. Then use random mode (`-r`) and set a number of runs (`-n`) for active fuzzing.

---

## Installation

1. Python 3
2. `gatttool` from BlueZ suite
3. (Optional) `curses` for TUI

Clone or download glizzy.py and make it executable:

```bash
chmod +x glizzy.py
```

---

## Usage

```bash
sudo python3 glizzy.py <MAC> [options]
```

Root is required for BLE access via `gatttool`.

---

## Arguments

### Positional

| Argument | Description                            |
|----------|----------------------------------------|
| `MAC`    | BLE device MAC address (`AA:BB:CC:DD:EE:FF`) |

### Options

| Long Flag           | Short | Arg       | Default   | Description |
|---------------------|-------|-----------|-----------|-------------|
| `--services`        | `-s`  | hex range | —         | One or more GATT service ranges (e.g. `0x0001-0x0009`) |
| `--handles`         | `-H`  | hex range | —         | One or more handles or handle ranges |
| `--uuid`            | `-u`  | prefix    | —         | Filter services by UUID prefix |
| `--chars`           | `-c`  | int       | `10`      | Max payload length in bytes for incremental mode |
| `--runs`            | `-n`  | int       | —         | Static-length mode: run this many write attempts |
| `--addr-type`       | `-a`  | type      | `public`  | BLE address type: `public` or `random` |
| `--random`          | `-r`  | flag      | off       | Randomize payload instead of all zeroes |
| `--prefix`          | `-p`  | hex       | —         | Prefix to prepend to each payload |
| `--log`             | `-l`  | file      | —         | Log output to specified file (still prints to terminal) |
| `--read-only`       |       | flag      | off       | Only read values; no writes performed |
| `--delay`           |       | float     | `0`       | Delay (seconds) between write operations |
| `--notify`          |       | flag      | off       | Listen for notifications after writes |
| `--tui`             |       | flag      | off       | Enable interactive TUI if `curses` is available |
| `--help`            | `-h`  |           |           | Show help message |

---

## Modes of Operation

### Incremental Fuzzing (Default)

Tests increasing payload lengths (1 to `--chars`).

```bash
sudo python3 glizzy.py AA:BB:CC:DD:EE:FF -s 0x000d-0x000d -c 5
```

### Static-Length Mode

Repeats fixed-length writes (`--chars`) for N runs.

```bash
sudo python3 glizzy.py AA:BB:CC:DD:EE:FF -H 0x000f -c 8 -n 10 -r
```

### Read-Only Mode

Only read characteristics from discovered services.

```bash
sudo python3 glizzy.py AA:BB:CC:DD:EE:FF --read-only
```

### TUI Mode

Provides a live terminal dashboard with handle info, progress, and elapsed time.

```bash
sudo python3 glizzy.py AA:BB:CC:DD:EE:FF --tui
```

Requires `curses` module to be installed.

---

## Color Legend

| Symbol | Meaning                                                      |
|--------|--------------------------------------------------------------|
| ✔      | Write succeeded and readback was successful (Green)         |
| ✖      | Write failed (Red)                                          |
| ?      | Likely valid handle, but input length not accepted (Yellow) |
|        | Notification was observed after write                        |

---

## Examples

1. Fuzz specific handle with incremental lengths

```bash
sudo python3 glizzy.py AA:BB:CC:DD:EE:FF -H 0x000d -c 10
```

2. Write fixed-length random hex strings with a prefix

```bash
sudo python3 glizzy.py AA:BB:CC:DD:EE:FF -H 0x000f -c 6 -n 5 -r -p 9d
```

Payloads like: `9dXX`, where `XX` is random

3. Filter services by UUID prefix before fuzzing

```bash
sudo python3 glizzy.py AA:BB:CC:DD:EE:FF -u 00005001 -c 6
```

---

## Output

Results are:
- Displayed live on the terminal
- Optionally logged to a file (via `--log`)
- Saved as JSON in `glizzy_results.json` upon completion or interruption

---

## Interrupting

Press `Ctrl+C` to interrupt the scan gracefully. Results will still be saved.

