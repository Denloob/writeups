#!/usr/bin/env python3
from z3 import *

FLAG_LEN = 48
flag = [BitVec("flag_%d" % i, 32) for i in range(FLAG_LEN)]

conditions = [
    flag[0 + 0] == 98,
    flag[1 + 0] == 119,
    flag[2 + 0] == 99,
    flag[3 + 0] == 116,
    flag[4 + 0] == 102,
    flag[5 + 0] == 123,
    flag[47 + 0] == 125,
    flag[3 + 8] == 45,
    flag[9 + 8] == 45,
    flag[15 + 8] == 45,
    flag[21 + 8] == 45,
    flag[27 + 8] == 45,
    flag[33 + 8] == 45,
    flag[13 + 5] < flag[14 + 5],
    (flag[2 + 4] ^ flag[30 + 4]) == 100,
    flag[14 + 4] < flag[17 + 4],
    flag[2 + 34] * flag[8 + 34] == 7654,
    flag[5 + 4] < flag[32 + 4],
    flag[12 + 7] > flag[30 + 7],
    flag[12 + 7] == flag[31 + 7],
    flag[0 + 13] * flag[14 + 13] == 3417,
    flag[1 + 23] > flag[3 + 23],
    flag[7 + 23] < flag[13 + 23],
    flag[8 + 11] > flag[21 + 11],
    flag[28 + 6] + flag[34 + 6] == 103,
    (flag[10 + 9] ^ flag[11 + 9]) == 102,
    (flag[1 + 19] ^ flag[19 + 19]) == 102,
    flag[15 + 22] + flag[23 + 22] == 133,
    flag[10 + 2] + flag[41 + 2] == 146,
    flag[4 + 6] + flag[40 + 6] == 126,
    flag[7 + 21] > flag[23 + 21],
    flag[2 + 6] < flag[32 + 6],
    (flag[5 + 21] ^ flag[13 + 21]) == 97,
    (flag[18 + 16] ^ flag[26 + 16]) == 101,
    flag[2 + 6] < flag[28 + 6],
    flag[0 + 8] == flag[10 + 8],
    flag[10 + 2] * flag[19 + 2] == 6699,
    (flag[12 + 13] ^ flag[18 + 13]) == 123,
    (flag[4 + 2] ^ flag[14 + 2]) == 21,
    flag[5 + 10] < flag[30 + 10],
    (flag[21 + 9] ^ flag[22 + 9]) == 14,
    flag[13 + 12] * flag[33 + 12] == 4335,
    (flag[12 + 4] ^ flag[27 + 4]) == 10,
    (flag[2 + 24] ^ flag[22 + 24]) == 28,
    flag[21 + 0] > flag[42 + 0],
    flag[11 + 3] > flag[30 + 3],
    flag[14 + 1] == flag[31 + 1],
    flag[14 + 8] * flag[18 + 8] == 4264,
    flag[15 + 3] < flag[19 + 3],
    flag[14 + 0] + flag[15 + 0] == 132,
    flag[5 + 5] * flag[28 + 5] == 3840,
    flag[2 + 22] + flag[12 + 22] == 135,
    flag[14 + 8] + flag[17 + 8] == 103,
    flag[1 + 8] * flag[12 + 8] == 3417,
    flag[8 + 11] > flag[35 + 11],
    flag[4 + 6] + flag[22 + 6] == 132,
    flag[25 + 2] + flag[28 + 2] == 137,
    (flag[3 + 9] ^ flag[5 + 9]) == 25,
    flag[19 + 1] * flag[42 + 1] == 3519,
    flag[4 + 28] * flag[6 + 28] == 2448,
    flag[14 + 1] + flag[38 + 1] == 120,
    flag[6 + 7] * flag[23 + 7] == 3570,
    flag[1 + 23] + flag[21 + 23] == 154,
    (flag[3 + 17] ^ flag[11 + 17]) == 103,
    flag[8 + 10] + flag[15 + 10] == 100,
    flag[1 + 6] * flag[15 + 6] == 6003,
    flag[8 + 17] == flag[17 + 17],
    (flag[2 + 6] ^ flag[3 + 6]) == 114,
    (flag[10 + 9] ^ flag[27 + 9]) == 12,
    (flag[4 + 6] ^ flag[8 + 6]) == 100,
    flag[21 + 10] + flag[36 + 10] == 150,
]

solver = Solver()
solver.add(conditions)

# Make sure all the characters are ascii characters
for ch in flag:
    solver.add(z3.And(ch >= 32, ch <= 126))

solution_history = set()

while solver.check() == sat:
    model = solver.model()
    result = [chr(model[flag[i]].as_long()) for i in range(FLAG_LEN)]
    result_str = str("".join(result))

    # Skip existing solutions
    if result_str in solution_history: continue

    solution_history.add(result_str)
    print(result_str)
