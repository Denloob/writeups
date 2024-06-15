# format \[460 Points] (17 Solves)
```
Format String in Python safe to use
```
We are given an [attachment](./forCTFD) and `nc 20.80.240.190 4213`
---

## Writeup
We need to guess both the length of a random array and where strings, bools, floats and ints are located
and all of this using only `%f`, `%d`, `%r` and `%s`. \
Thankfully `%r` and `%s` can print everything, but `%f` and `%d` can only print ints, bools and floats. \
The key here is that here's a different error for trying to print a string with `%f` from tring to print the string with `%d`. \ 
Thus what we can do is "scan" for strings using a \
`... %f %d %d %d...`
- If we get an float error, we know that the problem was the %f. -> instead of %f there should have been a string
- If we get an int error, then we know that the problem was not the %f. -> %f can still be %d or %f. It's an int :)

And that's exactly what the solve script does. \
[solve.py](./solve.py)

**Flag:** `AKASEC{NUMB3R5_C4NT_B3_STR1NG5_BUT_TH3Y_C4N_B3_B00L34N}`

## Other solutions
It's also possible to not fill the buffer completely as python priorities wrong formats over count mismatch errors. \
Writing the solve script is left as an exercise to the reader :)
