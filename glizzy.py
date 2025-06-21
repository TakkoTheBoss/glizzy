import argparse
import random
import subprocess
import shlex
import json
import re
import sys
from collections import defaultdict

# ANSI color codes
GREEN   = '\033[92m'
RED     = '\033[91m'
YELLOW  = '\033[93m'
CYAN    = '\033[96m'
MAGENTA = '\033[95m'
GRAY    = '\033[90m'
RESET   = '\033[0m'

class BLEFuzzer:
    def __init__(self, args):
        self.mac_address     = args.mac
        self.le_address_type = args.addr_type
        self.chars_to_write  = args.chars
        self.service_ranges  = args.services or []
        self.handle_ranges   = args.handles or []
        self.target_uuid     = args.uuid.lower() if args.uuid else None
        self.random_mode     = args.random
        self.runs            = args.runs
        self.results         = []

    @staticmethod
    def parse_hex_range(s):
        parts = s.split('-')
        if len(parts) == 1:
            val = int(parts[0], 16)
            return [(val, val)]
        start = int(parts[0], 16)
        end   = int(parts[1], 16)
        return [(start, end)]

    def discover(self):
        print(f"{MAGENTA}==> DISCOVER SERVICES{RESET}")
        if self.handle_ranges:
            self.services = [{'start':a, 'end':b, 'uuid':'manual'} for a,b in self.handle_ranges]
        elif self.service_ranges:
            self.services = [{'start':a, 'end':b, 'uuid':'manual'} for a,b in self.service_ranges]
        else:
            cmd = f"gatttool --addr-type={self.le_address_type} --primary --device={self.mac_address}"
            proc = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            raw, _ = proc.communicate()
            text = raw.decode('utf-8', 'ignore')
            print(f"{MAGENTA}Discovered Primary Services:\n{text}{RESET}")
            services = []
            for line in text.splitlines():
                m = re.search(
                   r'attr handle = (0x[0-9a-f]+), end grp handle = (0x[0-9a-f]+) '
                   r'uuid: ([0-9a-fA-F-]+)', line)
                if m:
                    start, end, uuid = m.groups()
                    services.append({
                        'start':int(start,16),
                        'end':  int(end,16),
                        'uuid': uuid.lower()
                    })
            self.services = services

        if self.target_uuid:
            filtered = [
                svc for svc in self.services
                if svc.get('uuid','').startswith(self.target_uuid)
            ]
            if not filtered:
                print(f"{RED}No services found matching UUID {self.target_uuid}{RESET}")
                sys.exit(1)
            self.services = filtered

    def fuzz(self):
        print(f"{MAGENTA}==> FUZZING HANDLES{RESET}")
        print()
        for svc in self.services:
            a, b, u = svc['start'], svc['end'], svc['uuid']
            print(f"{CYAN}Service handles {hex(a)[2:]}-{hex(b)[2:]} (UUID: {u}){RESET}")
            if self.runs:
                for handle in range(a, b+1):
                    hstr = f'0x{handle:04x}'
                    for _ in range(self.runs):
                        length = self.chars_to_write
                        payload = (
                            ''.join(random.choice('0123456789abcdef')
                                    for _ in range(length))
                            if self.random_mode else
                            '0'*length
                        )
                        self._attempt(hstr, length, payload)
            else:
                for handle in range(a, b+1):
                    hstr = f'0x{handle:04x}'
                    for length in range(1, self.chars_to_write+1):
                        payload = (
                            ''.join(random.choice('0123456789abcdef')
                                    for _ in range(length))
                            if self.random_mode else
                            '0'*length
                        )
                        self._attempt(hstr, length, payload)
            print()

    def _attempt(self, hstr, length, fuzz_input):
        write_cmd = (
            f"gatttool --addr-type={self.le_address_type} "
            f"--device={self.mac_address} --char-write-req "
            f"--handle={hstr} --value={fuzz_input}"
        )
        wp = subprocess.Popen(
            shlex.split(write_cmd),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        wraw, werr = wp.communicate()
        wcode = wp.returncode
        wresp = (wraw.decode('utf-8','ignore').strip() or
                 werr.decode('utf-8','ignore').strip())

        if wcode == 0 and 'was written successfully' in wresp:
            read_cmd = (
                f"gatttool --addr-type={self.le_address_type} "
                f"--device={self.mac_address} --char-read --handle={hstr}"
            )
            rp = subprocess.Popen(
                shlex.split(read_cmd),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            rraw, _ = rp.communicate()
            rb = rraw.decode('utf-8','ignore').strip()
            self.results.append({
                'handle':hstr, 'length':length,
                'exit':0, 'readback':rb
            })
            print(
                f"{GREEN}✔{RESET} {CYAN}{hstr}{RESET} len={GRAY}{length:<3}{RESET}"
                f" input={MAGENTA}0x{fuzz_input}{RESET}"
                f" -> {GREEN}OK{RESET} readback={CYAN}{rb}{RESET}"
            )
        else:
            detail = wresp or f"err={wcode}"
            mark = '✖'
            color = RED
            if "Attribute value length is invalid" in detail:
                mark = '?'
                color = YELLOW
            self.results.append({
                'handle':hstr, 'length':length,
                'exit':wcode, 'readback':None
            })
            print(
                f"{color}{mark}{RESET} {CYAN}{hstr}{RESET} len={GRAY}{length:<3}{RESET}"
                f" input={MAGENTA}0x{fuzz_input}{RESET}"
                f" -> {detail}"
            )

    def summarize(self):
        summary = defaultdict(lambda:{'max_success':0, 'first_fail':None})
        for e in self.results:
            h = e['handle']
            if e['exit'] == 0:
                summary[h]['max_success'] = max(summary[h]['max_success'], e['length'])
            elif summary[h]['first_fail'] is None:
                summary[h]['first_fail'] = e['length']

        print(f"{MAGENTA}==> SUMMARY{RESET}")
        for h, data in summary.items():
            print(f"{CYAN}{h}{RESET}: max {GREEN}{data['max_success']}{RESET} bytes, "
                  f"fail at {RED}{data['first_fail']}{RESET}")

        with open('blefuzz_results.json', 'w') as f:
            json.dump(self.results, f, indent=2)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='BLE GATT Handle Fuzzer')
    parser.add_argument('mac', help='BLE device MAC')
    parser.add_argument(
        '-s','--services', nargs='+',
        help='Service ranges e.g. 0x1-0x9 0x12'
    )
    parser.add_argument(
        '-H','--handles', nargs='+',
        help='Explicit handles e.g. 0x03 0x04-0x05'
    )
    parser.add_argument(
        '-u','--uuid',
        help='Filter by service UUID (prefix OK)'
    )
    parser.add_argument(
        '-c','--chars', type=int, default=10,
        help='Max chars to write'
    )
    parser.add_argument(
        '-n','--runs', type=int,
        help='Number of static-length fuzz runs'
    )
    parser.add_argument(
        '-a','--addr-type',
        choices=['public','random'], default='public',
        help='LE address type'
    )
    parser.add_argument(
        '-r','--random', action='store_true',
        help='Use random hex fuzz'
    )
    args = parser.parse_args()
    if args.services:
        args.services = [
            rng for r in args.services
            for rng in BLEFuzzer.parse_hex_range(r)
        ]
    if args.handles:
        args.handles = [
            rng for r in args.handles
            for rng in BLEFuzzer.parse_hex_range(r)
        ]
    fuzzer = BLEFuzzer(args)
    fuzzer.discover()
    fuzzer.fuzz()

