from pwn import u64

BINARY = open("./maybe_checker", "rb").read()

FUNCS_START = 0x2040  # The address the array in the binary
FUNC_COUNT = 0x3c

for arr_idx in range(FUNC_COUNT):
    bin_idx = FUNCS_START + arr_idx * 9

    offset = BINARY[bin_idx]
    addr = BINARY[bin_idx + 1 : bin_idx + 9]

    print(hex(u64(addr)), offset)
