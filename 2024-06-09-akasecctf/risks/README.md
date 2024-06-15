# Risks \[205 Points] (44 Solves)
```
theres this pretty cool isa called riscv it sounds awesome.
```
Attached is [chall](./chall)
---

## Writeup

As the title and the description suggests, it's a rev chall compiled for riscv. \

Opening the binary in Ghidra we can find multiple functions responsible for manipulating
(or *"hashing"*) our input and then compares it to some values. Thankfully all the
operations used are reversable, so we don't even need to use z3. \
Using python I took all the manipulations done on the input, reversed the operations
and executed the code.

[solve.py](./solve.py)

**Flag:** `akasec{1n_my_b4g_0n3_s3c0nd_0n3}`
