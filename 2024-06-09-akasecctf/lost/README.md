# lost
```
Do you know the feelling of losing a part of you !!
```
We are given 2 [attachments](./attachments).

---

## Writeup

This is an RSA challange, and although the p and q are secure, e is very small
```py
e = 2
p = getPrime(256)
q = getPrime(256)
n = p * q
```

Additionally we know part of the flag,
```py
>>> long_to_bytes(724154397787031699242933363312913323086319394176220093419616667612889538090840511507392245976984201647543870740055095781645802588721)
b'AKASEC{c0pp3r5m17h_4774ck_1n_1ov3_v\xb1\x13q\x9f\xe3\xe4\xa1\xe2\x9b\xd5,\xfe\x14\\q\x99\xb9\x0c\xca1'
```

The flag hints us at [Coppersmith method](<https://www.wikiwand.com/en/Coppersmith_method>), which says that if we take the RSA formula

```
c ≡ m^(e) (mod n)
```

Rearrange it a bit

```
m^2 - c ≡ 0 (mod n)
```

We could solve it. But how?

Let's imagine it wasn't under modulo, we could easily solve it!

```
m^2 - c = 0
```
Which is exactly like
```
x^2 - 511316.. = 0
```

The problem though is that there is a modulo. Thankfully, in this case, we can still solve it using the Coppersmith method

It basically says that we could say that our expression is
```
F(x) ≡ x^2 - 511316... (mod n)
```
And we want to find an x for which
```
F(x) ≡ 0 (mod n)
```

So instead of solving it, we find a different, polynomial function `f`, which is similar to F in a way that for the same x as above,
```
f(x) ≡ 0 (mod n)
```
And if the constants in the polynomial are small enough, so that |f(x)| < n, f(x) is equal to 0 and this also means that F(x) is equal to zero!

How to find these functions is a bit complicated so I won't explain it here, but you are more than welcome to explore the topic on your own.

The problem though that it's very hard, if not impossible to find a function `f` for an `x` so large. \
Thankfully, we know part of the message! So we can use that to find only the missing part

And now when we know the `x` we know the flag.

Let's implement this using the math sage.

```py
#!/usr/bin/env sage

from sage.all import *
from Crypto.Util.number import long_to_bytes, bytes_to_long

n = 5113166966960118603250666870544315753374750136060769465485822149528706374700934720443689630473991177661169179462100732951725871457633686010946951736764639
c = 329402637167950119278220170950190680807120980712143610290182242567212843996710001488280098771626903975534140478814872389359418514658167263670496584963653
cor_m = 724154397787031699242933363312913323086319394176220093419616667612889538090840511507392245976984201647543870740055095781645802588721
e = 2

# If you want nice value for `x`, you could zero out the unknown part of cor_m, like I did in solve.sage, although this works just as well

P.<x> = PolynomialRing(Zmod(n))
f = (cor_m + x)^e - c
f = f.monic()
missing_part = f.small_roots()[0]

print(long_to_bytes(int(cor_m + missing_part)).decode())
```

**Flag:** `AKASEC{c0pp3r5m17h_4774ck_1n_1ov3_w17h_5m4ll_3xp0n3nts}`
