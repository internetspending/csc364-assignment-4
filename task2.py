"""
Task 2: Cracking bcrypt hashes from a shadow file
CPE-321 Cryptographic Hash Functions Lab

Strategy: dictionary attack using the NLTK word corpus (6-10 letter words),
parallelised across all available CPU cores via multiprocessing.Pool.

Usage:
    python task2.py                        # crack ALL users (hours on high wf)
    python task2.py --users Bilbo Gandalf  # crack specific users only
    python task2.py --wf-max 9             # only crack users with workfactor <= 9
"""

import argparse
import bcrypt
import multiprocessing as mp
import sys
import time
from functools import partial
from pathlib import Path

import nltk
nltk.download('words', quiet=True)
from nltk.corpus import words as nltk_words


# ── Word list ─────────────────────────────────────────────────────────────────

def build_wordlist() -> list[str]:
    """Filter NLTK corpus to lowercase words between 6 and 10 letters."""
    wl = [w.lower() for w in nltk_words.words()
          if w.isalpha() and 6 <= len(w) <= 10]
    # deduplicate while preserving order
    seen: set[str] = set()
    unique = []
    for w in wl:
        if w not in seen:
            seen.add(w)
            unique.append(w)
    return unique


# ── Shadow file parser ────────────────────────────────────────────────────────

def parse_shadow(path: str) -> dict[str, bytes]:
    """
    Parse a shadow file of the form:
        User:$2b$WF$<22-char-salt><hash>
    Returns {username: full_hash_bytes}.
    """
    entries: dict[str, bytes] = {}
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        user, hash_str = line.split(':', 1)
        entries[user] = hash_str.encode()
    return entries


# ── Per-process worker ────────────────────────────────────────────────────────

def _try_chunk(chunk: list[str], stored_hash: bytes) -> str | None:
    """
    Called in a worker process.
    Iterates over `chunk` and returns the matching word, or None.
    """
    for word in chunk:
        try:
            if bcrypt.checkpw(word.encode(), stored_hash):
                return word
        except Exception:
            continue
    return None


# ── Cracker ───────────────────────────────────────────────────────────────────

def crack_user(username: str, stored_hash: bytes,
               wordlist: list[str], num_cores: int) -> tuple[str | None, float]:
    """
    Distribute `wordlist` across `num_cores` processes and return the
    cracked password (or None) plus wall-clock time.
    """
    chunk_size = max(1, len(wordlist) // num_cores)
    chunks = [wordlist[i:i + chunk_size]
              for i in range(0, len(wordlist), chunk_size)]

    worker = partial(_try_chunk, stored_hash=stored_hash)

    start = time.perf_counter()
    result = None

    # Parse workfactor for ETA display
    parts = stored_hash.decode().split('$')
    wf = int(parts[2]) if len(parts) >= 3 else '?'
    print(f"  [{username}] workfactor={wf}  cores={num_cores}  "
          f"words={len(wordlist):,}  chunks={len(chunks)}")

    with mp.Pool(num_cores) as pool:
        for found in pool.imap_unordered(worker, chunks, chunksize=1):
            if found is not None:
                result = found
                pool.terminate()
                break

    elapsed = time.perf_counter() - start
    return result, elapsed


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="bcrypt dictionary cracker")
    parser.add_argument('--shadow', default='shadow.txt',
                        help='Path to shadow file (default: shadow.txt)')
    parser.add_argument('--users', nargs='+', default=None,
                        help='Crack only these users (default: all)')
    parser.add_argument('--wf-max', type=int, default=99,
                        help='Skip users whose workfactor exceeds this value')
    parser.add_argument('--cores', type=int, default=mp.cpu_count(),
                        help=f'Number of CPU cores (default: {mp.cpu_count()})')
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print("TASK 2: bcrypt Dictionary Cracker")
    print(f"{'='*60}")
    print(f"  Shadow file : {args.shadow}")
    print(f"  Cores       : {args.cores}")
    print(f"  WF max      : {args.wf_max}\n")

    # Load resources
    print("  Loading NLTK wordlist...", end=' ', flush=True)
    wordlist = build_wordlist()
    print(f"{len(wordlist):,} words (6-10 letters)")

    print("  Parsing shadow file...", end=' ', flush=True)
    shadow = parse_shadow(args.shadow)
    print(f"{len(shadow)} users\n")

    # Optionally filter users
    targets = args.users if args.users else list(shadow.keys())
    targets = [u for u in targets if u in shadow]

    # Filter by workfactor
    def get_wf(h: bytes) -> int:
        try:
            return int(h.decode().split('$')[2])
        except Exception:
            return 99

    targets = [u for u in targets if get_wf(shadow[u]) <= args.wf_max]

    if not targets:
        print("  No matching users to crack. Adjust --users or --wf-max.")
        sys.exit(0)

    print(f"  Cracking {len(targets)} user(s): {', '.join(targets)}\n")

    # Crack each user sequentially (parallelism is within each user's cracking)
    results: list[tuple[str, str | None, float]] = []
    for username in targets:
        print(f"  Cracking {username}...")
        pw, elapsed = crack_user(username, shadow[username], wordlist, args.cores)
        status = f"'{pw}'" if pw else "NOT FOUND"
        print(f"  → {username}: {status}  ({elapsed:.1f}s)\n")
        results.append((username, pw, elapsed))

    # Summary table
    print(f"\n{'='*60}")
    print("RESULTS")
    print(f"{'='*60}")
    print(f"  {'User':<12}  {'Password':<16}  {'Time (s)':>10}")
    print("  " + "-"*44)
    for username, pw, elapsed in results:
        pw_str = pw if pw else "NOT FOUND"
        print(f"  {username:<12}  {pw_str:<16}  {elapsed:>10.1f}")


if __name__ == '__main__':
    # Required on macOS/Windows for multiprocessing
    mp.freeze_support()
    main()
