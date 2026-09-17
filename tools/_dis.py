#!/usr/bin/env python3
"""Disassemble a range of GameAssembly.dll via the live Gadget (read-only).

Usage: python3 tools/_dis.py <addr_hex> [length] [--grep VA1,VA2,...]

Prints a capstone disassembly. With --grep, marks instructions whose operand
mentions any of the given VAs (used to spot virtual-call slots).
"""
import sys, os, json, subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import frida  # noqa
from capstone import Cs, CS_ARCH_X86, CS_MODE_64  # noqa


def load_driver(name):
    p = os.path.join(ROOT, 'tools', 'build', name + '_run.js')
    return open(p).read()


def read(addr, ln):
    dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
    s = dev.attach('Gadget')
    sc = s.create_script(load_driver('_vt'))
    sc.load()
    res = sc.exports_sync.raw(addr, ln)
    s.detach()
    return bytes.fromhex(res['hex']), res['rva']


def main():
    addr = int(sys.argv[1], 16)
    ln = int(sys.argv[2], 16) if len(sys.argv) > 2 and not sys.argv[2].startswith('--') else 0x200
    grep = []
    if '--grep' in sys.argv:
        grep = [int(x, 16) for x in sys.argv[sys.argv.index('--grep') + 1].split(',')]

    code, rva = read(addr, ln)
    print('# VA 0x%x  RVA %s  (%d bytes)' % (addr, rva, ln))
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for ins in md.disasm(code, addr):
        mark = ''
        try:
            for op in ins.operands:
                if op.type == 3 and op.imm in grep:  # X86_OP_IMM
                    mark = '   <== TARGET'
                elif op.type == 2:  # X86_OP_MEM
                    disp = op.mem.disp
                    # rip-relative -> absolute
                    abs_ = (ins.address + ins.size + disp) & 0xffffffffffffffff
                    for g in grep:
                        if disp == g or abs_ == g:
                            mark = '   <== TARGET(mem)'
        except Exception:
            pass
        print('0x%x  %-10s %s%s' % (ins.address, ins.mnemonic, ins.op_str, mark))


if __name__ == '__main__':
    main()
