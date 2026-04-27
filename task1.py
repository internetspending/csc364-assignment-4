"""
Task 1: Exploring Pseudo-Randomness and Collision Resistance
CPE-321 Cryptographic Hash Functions Lab
"""

import hashlib
import random
import string
import time
import matplotlib.pyplot as plt


# ── Helpers ───────────────────────────────────────────────────────────────────

def sha256_hex(s: str) -> str:
    """Return the full SHA256 digest of a string as a hex string."""
    return hashlib.sha256(s.encode()).hexdigest()


def truncated_hash(s: str, bits: int) -> int:
    """Return the SHA256 digest of s, truncated to the lowest `bits` bits."""
    full = int(sha256_hex(s), 16)
    mask = (1 << bits) - 1
    return full & mask


def flip_one_bit(s: str) -> str:
    """Return a new string that differs from s by exactly 1 bit."""
    b = bytearray(s.encode())
    byte_idx = random.randrange(len(b))
    bit_idx = random.randrange(8)
    b[byte_idx] ^= (1 << bit_idx)
    # decode with replace in case the flip produced invalid UTF-8
    return b.decode(errors='replace')


def hamming_distance_bits(h1: str, h2: str) -> int:
    """Count differing bits between two hex digest strings."""
    n1, n2 = int(h1, 16), int(h2, 16)
    return bin(n1 ^ n2).count('1')


def random_str(length: int = 10) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


# ── Task 1a: Hash arbitrary inputs ───────────────────────────────────────────

def task_1a():
    print("\n" + "="*60)
    print("TASK 1a: SHA256 Hashes of Arbitrary Inputs")
    print("="*60)
    inputs = ["Hello, World!", "CPE321", "Cryptography", "SaltedInput123", "a"]
    for msg in inputs:
        print(f"  Input : {msg!r}")
        print(f"  SHA256: {sha256_hex(msg)}\n")


# ── Task 1b: Avalanche effect (Hamming distance 1 inputs) ────────────────────

def task_1b():
    print("\n" + "="*60)
    print("TASK 1b: Strings with Input Hamming Distance = 1 bit")
    print("="*60)
    print("Observation: even a single flipped bit causes ~half the digest bits to change.\n")

    for trial in range(3):
        s1 = ''.join(random.choices(string.ascii_letters, k=10))
        s2 = flip_one_bit(s1)
        h1, h2 = sha256_hex(s1), sha256_hex(s2)
        diff_bits  = hamming_distance_bits(h1, h2)
        diff_bytes = diff_bits / 8

        print(f"  Trial {trial+1}:")
        print(f"    Input 1 : {s1!r}")
        print(f"    Input 2 : {s2!r}  (1-bit flip of input 1)")
        print(f"    H(s1)   : {h1}")
        print(f"    H(s2)   : {h2}")
        print(f"    Differing bits in digest : {diff_bits} / 256  (~{diff_bytes:.1f} bytes differ)\n")


# ── Task 1c: Birthday-attack collision on truncated hashes ───────────────────

def find_collision_birthday(bits: int, max_attempts: int = 15_000_000):
    """
    Birthday attack: store each (truncated_hash -> input) in a dict.
    The first time we see a repeated hash value we have a collision.
    Expected number of hashes before collision ≈ sqrt(pi/2 * 2^bits).
    """
    seen: dict[int, str] = {}
    start = time.perf_counter()

    for attempt in range(1, max_attempts + 1):
        s = random_str(10)
        h = truncated_hash(s, bits)

        if h in seen and seen[h] != s:
            elapsed = time.perf_counter() - start
            return seen[h], s, attempt, elapsed

        seen[h] = s

    elapsed = time.perf_counter() - start
    return None, None, max_attempts, elapsed


def task_1c():
    print("\n" + "="*60)
    print("TASK 1c: Finding Collisions in Truncated SHA256")
    print("="*60)
    print(f"  {'Bits':>4}  {'Inputs Tried':>14}  {'Time (s)':>10}  {'Input 1':>12}  {'Input 2':>12}  Hash")
    print("  " + "-"*80)

    bit_sizes, times, input_counts = [], [], []

    for bits in range(8, 52, 2):
        m1, m2, attempts, elapsed = find_collision_birthday(bits)

        if m1:
            h_val = hex(truncated_hash(m1, bits))
            print(f"  {bits:>4}  {attempts:>14,}  {elapsed:>10.4f}  {m1:>12}  {m2:>12}  {h_val}")
        else:
            print(f"  {bits:>4}  {'TIMEOUT':>14}  {elapsed:>10.4f}  {'--':>12}  {'--':>12}")

        bit_sizes.append(bits)
        times.append(elapsed)
        input_counts.append(attempts)

    # ── Graphs ────────────────────────────────────────────────────────────────
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))

    ax1.plot(bit_sizes, times, 'b-o', markersize=5)
    ax1.set_xlabel("Digest Size (bits)")
    ax1.set_ylabel("Collision Time (s)")
    ax1.set_title("Digest Size vs Collision Time")
    ax1.grid(True)

    ax2.plot(bit_sizes, input_counts, 'r-o', markersize=5)
    ax2.set_xlabel("Digest Size (bits)")
    ax2.set_ylabel("Number of Inputs")
    ax2.set_title("Digest Size vs Number of Inputs")
    ax2.grid(True)

    plt.tight_layout()
    plt.savefig("collision_analysis.png", dpi=150)
    print("\n  Graphs saved → collision_analysis.png")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    task_1a()
    task_1b()
    task_1c()
