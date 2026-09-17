#!/usr/bin/env python3
"""Disassemble a method body in the live process and resolve call targets.

Usage: python3 _dis.py <addr_hex> [nbytes]
"""
import frida, json, sys, os, subprocess
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ROOT = os.path.dirname(os.path.abspath(__file__))


def rpc(driver, export, *args):
    p = subprocess.run([os.path.join(ROOT, '.venv', 'bin', 'python'), os.path.join(ROOT, '_r.py'),
                        os.path.join(ROOT, driver), export] + [json.dumps(a) for a in args],
                       capture_output=True, text=True, timeout=180)
    return json.loads(p.stdout)


def main():
    addr = int(sys.argv[1], 16)
    n = int(sys.argv[2],0) if len(sys.argv) > 2 else 0x200
    data = bytes(rpc('../build/_lits_run.js', 'read', hex(addr), n))
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    targets = []
    ins = list(md.disasm(data, addr))
    for i in ins:
        if i.mnemonic == 'call' and i.operands and i.operands[0].type == 2:  # imm
            targets.append(i.operands[0].imm)
        if i.mnemonic in ('lea', 'mov') :
            for op in i.operands:
                if op.type == 3:  # mem
                    pass
    names = {}
    if targets:
        names = rpc('../build/_sym_run.js', 'sym', [hex(t) for t in targets])
    for i in ins:
        line = '%016x  %-8s %s' % (i.address, i.mnemonic, i.op_str)
        if i.mnemonic == 'call' and i.operands and i.operands[0].type == 2:
            t = i.operands[0].imm
            line += '   ; ' + names.get(hex(t).lower(), hex(t))
        print(line)


if __name__ == '__main__':
    main()
