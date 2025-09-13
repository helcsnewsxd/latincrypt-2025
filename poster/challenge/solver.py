import json
import random
from pwn import process
from Crypto.Util.number import GCD, isPrime, long_to_bytes
from functools import reduce
from collections import defaultdict
from hashlib import sha256 as Hash

SV = process(["python3", "./public-server.py"])
DBG = False


def show(m):
    if DBG:
        print(m)


def initialize(fst_time=False):
    if not fst_time:
        SV.sendlineafter(b"Choose your fate: R/J/I: ", b"I")

    SV.recvuntil(b"The Wheel decided this value be known to you: ")
    N = int(SV.recvline())
    show(f"[+] (Initialize) N = {N}")
    return N


def rotations():
    SV.sendlineafter(b"Choose your fate: R/J/I: ", b"R")

    spins = [int(x.strip()) for x in SV.recvline().strip()[1:-1].split(b",")]
    states = [int(x.strip()) for x in SV.recvline().strip()[1:-1].split(b",")]
    show(f"[+] (Rotations) Spins = {spins}")
    show(f"[+] (Rotations) States = {states}")
    return (spins, states)


def judgement(h, u, e, z):
    SV.sendlineafter(b"Choose your fate: R/J/I: ", b"J")
    SV.sendlineafter(
        b"Your message: ", json.dumps({"h": h, "u": u, "z": z, "e": e}).encode()
    )

    ln = SV.recvline()
    if ln in ["Punny attempt.", "you failed."]:
        return ""

    flag = ln.strip().split(b"The Wheel stopped spinning.. ")[1].decode()
    return flag


def get_spin_values_to_use(K):
    idx = defaultdict(int)
    for i in range(len(K)):
        idx[K[i]] = i

    pairs = []
    sum_dict = defaultdict(list)
    for x in K:
        for y in K:
            pairs.append((x, y))
            sum_dict[x + y].append((x, y))

    sol = []
    for a, c in pairs:
        for b, d in pairs:
            for e, g in sum_dict[a + c]:
                for f, h in sum_dict[b + d]:
                    if {a + d, b + c} == {e + h, f + g}:
                        sol.append(tuple([idx[x] for x in [a, b, c, d, e, f, g, h]]))
    return sol


def main():
    N, p = -1, -1
    while N == -1:
        N = initialize(fst_time=(p == -1))
        K, S = rotations()
        K = [0] + K

        # Get possible pairs and get p
        for i in range(1, len(K)):
            K[i] += K[i - 1]
        show(f"[+] Real spins = {K}")

        idx = get_spin_values_to_use(K)
        show(f"[+] Quantity of possible spin combinations: {len(idx)}")

        R = []
        for i in range(len(idx)):
            a, b, c, d, e, f, g, h = [S[j] for j in idx[i]]
            nwR = (a - b) * (c - d) - (e - f) * (g - h)
            if nwR != 0:
                R.append(nwR)

        show(f"[+] R list = {R}")
        p = reduce(GCD, R)
        show(f"[+] Number p = {p} obtained as GCD over {len(R)} numbers")
        show(f"[+] Is p a prime number? -> {isPrime(p)}")

        if not isPrime(p):
            N = -1
            continue

        # Get q
        q = N // p
        assert p * q == N

        # Judgement and obtain final flag
        phi = (p - 1) * (q - 1)
        g = 2
        z = phi

        u, e = -1, hex(-1)
        while u == -1:
            u = random.randint(1, N)
            e = Hash(b"".join([long_to_bytes(x) for x in [g, N, u]])).hexdigest()
            if GCD(int(e, 16), phi) != 1:
                # e^{-1} % phi doesn't exists
                u = -1

        d = pow(int(e, 16), -1, phi)
        h = pow(u, d, N)

        flag = judgement(h, u, e, z)
        print(f"[+] Obtained flag: {flag}")


if __name__ == "__main__":
    main()
