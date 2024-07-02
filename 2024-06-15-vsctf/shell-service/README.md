# shell-service \[480 Points] (45 Solves)
```
Here's the SHS access you needed. I just hope you remember your password.
```
Attached is [dist/](./dist)

---

## Writeup

Opening the attached binary in Ghidra, we see
```c
puts("Enter the password:");
fgets(password,11,stdin);
password_len = strlen(password);
if ((int)password_len != 10) {
  puts("Wrong password!");
  exit(0);
}
for (i = 0; i < 10; i = i + 1) {
  pass_ch = getPassChar(i);
  if (pass_ch != password[i]) {
    puts("Wrong password!");
    exit(0);
  }
}
puts("Welcome, admin!");
system("/bin/sh");
```

Alright, so wee need to guess the password, but what's it's value? \
Let's look at `getPassChar`. \
_**A lot**_ is going on in this function, so I will summarize:
1. It loads a tar archive
2. If the archive has a password.txt file (which we do have locally, but, presumably, not remotely) \
&nbsp;&nbsp;&nbsp;&nbsp;It will use the first line from the file. \
Otherwise \
&nbsp;&nbsp;&nbsp;&nbsp;Based on the index of the char, it load `{idx}.txt` from the tar, and it contains the password character.

3. `usleep(500000);` - sleeps for 500000 microseconds (0.5 seconds)
4. Returns the retrieved char

The 0.5 second sleep is suspicious, why would it be there? It looks to me like a timing attack! \
The idea is to submit passwords, and based on the time it takes the server to respond,
we can guess the correct character of the password.

Let's take an example:

- Attacker: `v`
- Server (after 0.5 sec): Wrong

Now we know the first character is not `v`, let's try the next one

- Attacker: `w`
- Server (after 1 sec): Wrong

And now we know that it's `w`!

It works because if the first character is invalid, it stops immediately after it checks it (thus it sleeps only for 0.5 secs). \
However if it is valid, it will check it for 0.5 sec, and then the next one for 0.5 sec (a total of 1 second).

I implemented this attack in a python script, with some utilities to make sure the delay wasn't a fluke.

[solve.py](./solve.py)

**Flag:** `vsctf{h0w_much_t1m3_d1d_1t_t4k3_to_r3m3mb3r?}`
