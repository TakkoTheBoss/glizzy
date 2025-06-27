#!/usr/bin/env python3
import argparse
import random
import subprocess
import shlex
import json
import re
import sys
import time
from collections import defaultdict

# Try to import curses for TUI
try:
    import curses
except ImportError:
    curses = None

# ANSI color codes
GREEN   = '\033[92m'
RED     = '\033[91m'
YELLOW  = '\033[93m'
CYAN    = '\033[96m'
MAGENTA = '\033[95m'
GRAY    = '\033[90m'
RESET   = '\033[0m'

# BLE property bit masks → human‐readable
PROPERTY_FLAGS = {
    0x01: "Broadcast",
    0x02: "Read",
    0x04: "Write without response",
    0x08: "Write",
    0x10: "Notify",
    0x20: "Indicate",
    0x40: "Authenticated Signed Writes",
    0x80: "Extended Properties"
}

class BLEFuzzer:
    def __init__(self, args):
        # Required
        self.mac_address     = args.mac
        self.le_address_type = args.addr_type

        # Fuzz settings
        self.chars_to_write  = args.chars
        self.runs            = args.runs
        self.random_mode     = args.random
        self.prefix          = args.prefix or ''
        self.delay           = args.delay or 0

        # Discovery filters
        self.service_ranges  = args.services or []
        self.handle_ranges   = args.handles or []
        self.target_uuid     = args.uuid.lower() if args.uuid else None

        # Modes
        self.read_only       = args.read_only
        self.notify_mode     = args.notify
        self.use_tui         = args.tui and curses is not None

        # Logging
        self.logfile         = args.log
        self.logstream       = open(self.logfile, 'w') if self.logfile else None

        # Internal state
        self.services        = []      # list of dicts {start,end,uuid}
        self.results         = []      # list of result dicts
        self.start_time      = None
        self.success_count   = 0
        self.fail_count      = 0

    def _log(self, msg):
        print(msg)
        if self.logstream:
            self.logstream.write(msg + "\n")
            self.logstream.flush()

    @staticmethod
    def parse_hex_range(s):
        parts = s.split('-')
        if len(parts) == 1:
            v = int(parts[0], 16)
            return [(v, v)]
        a, b = int(parts[0], 16), int(parts[1], 16)
        return [(a, b)]

    def discover(self):
        """Discover primary services and then characteristic descriptors with plain-English properties."""
        self._log(f"{MAGENTA}==> DISCOVER SERVICES{RESET}")
        # manual override
        if self.handle_ranges:
            self.services = [{'start':a,'end':b,'uuid':'manual'} for a,b in self.handle_ranges]
        elif self.service_ranges:
            self.services = [{'start':a,'end':b,'uuid':'manual'} for a,b in self.service_ranges]
        else:
            # default: primary services
            cmd = f"gatttool --addr-type={self.le_address_type} --primary --device={self.mac_address}"
            try:
                out = subprocess.check_output(shlex.split(cmd), stderr=subprocess.DEVNULL)
                text = out.decode('utf-8','ignore')
                self._log(text.strip())
                for line in text.splitlines():
                    m = re.search(
                        r"attr handle = (0x[0-9a-f]+), end grp handle = (0x[0-9a-f]+) uuid: ([0-9a-fA-F-]+)",
                        line
                    )
                    if m:
                        s, e, u = m.groups()
                        self.services.append({
                            'start': int(s,16),
                            'end':   int(e,16),
                            'uuid':  u.lower()
                        })
            except subprocess.CalledProcessError:
                self._log(f"{YELLOW}[!] Could not discover primary services{RESET}")
                sys.exit(1)

        # Filter by UUID prefix
        if self.target_uuid:
            filtered = [svc for svc in self.services if svc['uuid'].startswith(self.target_uuid)]
            if not filtered:
                self._log(f"{RED}No services matching UUID {self.target_uuid}{RESET}")
                sys.exit(1)
            self.services = filtered

        # Now discover characteristic descriptors
        self._log(f"{MAGENTA}==> CHARACTERISTIC DESCRIPTORS{RESET}")
        char_cmd = (
            f"gatttool --addr-type={self.le_address_type} "
            f"--device={self.mac_address} --char-desc"
        )
        try:
            crou = subprocess.check_output(shlex.split(char_cmd), stderr=subprocess.DEVNULL)
            ctext = crou.decode('utf-8','ignore')
            for line in ctext.splitlines():
                m2 = re.search(
                    r"handle: (0x[0-9a-f]+), char properties: (0x[0-9a-f]+), char value handle: (0x[0-9a-f]+), uuid: ([0-9a-fA-F-]+)",
                    line
                )
                if not m2:
                    continue
                handle_hex, prop_hex, val_handle, uuid = m2.groups()
                h = int(handle_hex,16)
                # only if within any discovered service range
                if not any(s['start'] <= h <= s['end'] for s in self.services):
                    continue
                prop_val = int(prop_hex,16)
                # decode bits
                names = [name for bit,name in PROPERTY_FLAGS.items() if prop_val & bit]
                names_str = ", ".join(names) if names else "None"
                self._log(f"{CYAN}{handle_hex}{RESET}: Properties [{names_str}], Value Handle={val_handle}, UUID={uuid}")
        except subprocess.CalledProcessError:
            self._log(f"{YELLOW}[!] Could not discover characteristics{RESET}")

    def _read_handle(self, hstr):
        cmd = f"gatttool --addr-type={self.le_address_type} --device={self.mac_address} --char-read --handle={hstr}"
        rp = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out,_ = rp.communicate()
        return out.decode('utf-8','ignore').strip()

    def _attempt(self, hstr, length, payload):
        write_cmd = (
            f"gatttool --addr-type={self.le_address_type} "
            f"--device={self.mac_address} --char-write-req "
            f"--handle={hstr} --value={payload}"
        )
        wp = subprocess.Popen(shlex.split(write_cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        wout,werr = wp.communicate()
        code = wp.returncode
        resp = (wout+werr).decode('utf-8','ignore').strip()

        success = (code==0 and "was written successfully" in resp)
        if success:
            rb = self._read_handle(hstr)
            self.results.append({'handle':hstr,'length':length,'exit':0,'readback':rb})
            self.success_count += 1
            self._log(f"{GREEN}✔{RESET} {CYAN}{hstr}{RESET} len={length:<3} input=0x{payload} -> {GREEN}OK{RESET} readback={CYAN}{rb}{RESET}")
        else:
            mark = '?' if "invalid" in resp.lower() else '✖'
            color = YELLOW if mark=='?' else RED
            self.results.append({'handle':hstr,'length':length,'exit':code,'readback':None})
            self.fail_count += 1
            self._log(f"{color}{mark}{RESET} {CYAN}{hstr}{RESET} len={length:<3} input=0x{payload} -> {resp}")

        if self.notify_mode:
            try:
                out = subprocess.check_output(
                    f"timeout 5 gatttool --device={self.mac_address} "
                    f"--addr-type={self.le_address_type} --listen",
                    shell=True, stderr=subprocess.DEVNULL
                )
                note = out.decode('utf-8','ignore').strip()
                if note:
                    self._log(f"{YELLOW}🔔 Notify: {note}{RESET}")
            except subprocess.CalledProcessError:
                pass

    def _curses_fuzz(self, stdscr):
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.clear()
        self.start_time = time.time()

        stdscr.addstr(0,2,"BLE Fuzzer TUI (press 'q' to quit)",curses.A_BOLD)
        row = 2
        for svc in self.services:
            stdscr.addstr(row,2,
                f"Service {hex(svc['start'])}–{hex(svc['end'])} UUID:{svc['uuid']}"
            )
            row += 1
        row += 1
        status_row = row

        for svc in self.services:
            for h in range(svc['start'], svc['end']+1):
                for length in ([self.chars_to_write]*self.runs if self.runs else range(1,self.chars_to_write+1)):
                    suffix_len = length - len(self.prefix)
                    suffix = ''.join(random.choice('0123456789abcdef') for _ in range(suffix_len)) if self.random_mode else '0'*suffix_len
                    payload = self.prefix + suffix

                    success_before = self.success_count
                    self._attempt(f"0x{h:04x}", length, payload)
                    success = self.success_count > success_before

                    elapsed = int(time.time() - self.start_time)
                    stdscr.addstr(status_row,2,
                        f"H:0x{h:04x} L:{length:<3} S:{self.success_count:<4} F:{self.fail_count:<4} E:{elapsed}s",
                        curses.A_REVERSE if not success else curses.A_NORMAL
                    )
                    stdscr.clrtoeol()
                    stdscr.refresh()
                    time.sleep(self.delay)

                    c = stdscr.getch()
                    if c in (ord('q'), ord('Q')):
                        return

        stdscr.nodelay(False)
        stdscr.addstr(status_row+2,2,"Fuzz complete. Press any key.",curses.A_BOLD)
        stdscr.getch()

    def fuzz(self):
        self.start_time = time.time()

        if self.read_only:
            self._log(f"{MAGENTA}==> READ-ONLY MODE{RESET}\n")
            for svc in self.services:
                a,b,u = svc['start'],svc['end'],svc['uuid']
                self._log(f"{CYAN}Reading {hex(a)}–{hex(b)} (UUID:{u}){RESET}")
                for h in range(a,b+1):
                    hstr = f"0x{h:04x}"
                    val  = self._read_handle(hstr)
                    self.results.append({'handle':hstr,'readback':val})
                    self._log(f"{GREEN}✔{RESET} {CYAN}{hstr}{RESET} -> {CYAN}{val}{RESET}")
            return

        if self.use_tui:
            curses.wrapper(self._curses_fuzz)
            return

        self._log(f"{MAGENTA}==> FUZZING HANDLES{RESET}\n")
        for svc in self.services:
            a,b,u = svc['start'],svc['end'],svc['uuid']
            self._log(f"{CYAN}Service {hex(a)}–{hex(b)} (UUID:{u}){RESET}")
            for h in range(a,b+1):
                hstr = f"0x{h:04x}"
                if self.runs:
                    for _ in range(self.runs):
                        length = self.chars_to_write
                        suffix_len = length - len(self.prefix)
                        suffix = ''.join(random.choice('0123456789abcdef') for _ in range(suffix_len)) if self.random_mode else '0'*suffix_len
                        self._attempt(hstr, length, self.prefix + suffix)
                        time.sleep(self.delay)
                else:
                    for length in range(1,self.chars_to_write+1):
                        suffix_len = length - len(self.prefix)
                        suffix = ''.join(random.choice('0123456789abcdef') for _ in range(suffix_len)) if self.random_mode else '0'*suffix_len
                        self._attempt(hstr, length, self.prefix + suffix)
                        time.sleep(self.delay)
            self._log("")

    def summarize(self):
        with open('glizzy_results.json','w') as f:
            json.dump(self.results, f, indent=2)
        self._log(f"{MAGENTA}==> RESULTS SAVED{RESET}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='GLIZZY — BLE GATT Handle Fuzzer / Reader')
    parser.add_argument('mac', help='BLE device MAC address')
    parser.add_argument('-s','--services', action='append', help='Service ranges (e.g. 0x1-0x9)')
    parser.add_argument('-H','--handles', action='append', help='Explicit handles (e.g. 0x0003 or 0x0007-0x000a)')
    parser.add_argument('-u','--uuid', help='Filter services by UUID prefix')
    parser.add_argument('-c','--chars', type=int, default=10, help='Max payload length for incremental mode')
    parser.add_argument('-n','--runs', type=int, help='Number of static-length writes')
    parser.add_argument('-a','--addr-type', choices=['public','random'], default='public', help='LE address type')
    parser.add_argument('-r','--random', action='store_true', help='Use random hex payloads')
    parser.add_argument('-p','--prefix', help='Hex prefix to prepend to payloads')
    parser.add_argument('-l','--log', help='Log output to file')
    parser.add_argument('--read-only', action='store_true', help='Only read current values, no fuzz')
    parser.add_argument('--delay', type=float, help='Delay between operations (seconds)')
    parser.add_argument('--notify', action='store_true', help='Listen for notifications after writes')
    parser.add_argument('--tui', action='store_true', help='Enable curses TUI dashboard')
    args = parser.parse_args()

    # Expand hex ranges
    if args.services:
        args.services = [rng for r in args.services for rng in BLEFuzzer.parse_hex_range(r)]
    if args.handles:
        args.handles = [rng for r in args.handles for rng in BLEFuzzer.parse_hex_range(r)]

    fuzzer = BLEFuzzer(args)
    try:
        fuzzer.discover()
        fuzzer.fuzz()
        fuzzer.summarize()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}==> INTERRUPTED{RESET}")
        fuzzer.summarize()
        sys.exit(1)

