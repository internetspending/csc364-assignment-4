"""
Task 2: Cracking bcrypt hashes from a shadow file
CPE-321 Cryptographic Hash Functions Lab

Usage:
    python task2.py                        # crack ALL users
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


def build_wordlist():
    """Filter NLTK corpus to lowercase words between 6 and 10 letters."""
    seen = set()
    unique = []
    for w in nltk_words.words():
        wl = w.lower()
        if wl.isalpha() and 6 <= len(wl) <= 10 and wl not in seen:
            seen.add(wl)
            unique.append(wl)
    return unique


def parse_shadow(path):
    """Return {username: hash_bytes} from a shadow file."""
    entries = {}
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        user, hash_str = line.split(':', 1)
        entries[user] = hash_str.encode()
    return entries


def _try_chunk(chunk, stored_hash):
    """Worker: try each word in chunk, return matching word or None."""
    for word in chunk:
        try:
            if bcrypt.checkpw(word.encode(), stored_hash):
                return word
        except Exception:
            continue
    return None


def get_wf(h):
    try:
        return int(h.decode().split('$')[2])
    except Exception:
        return 99


def crack_user(username, stored_hash, wordlist, num_cores):
    chunk_size = max(1, len(wordlist) // num_cores)
    chunks = [wordlist[i:i + chunk_size]
              for i in range(0, len(wordlist), chunk_size)]
    worker = partial(_try_chunk, stored_hash=stored_hash)
    wf = get_wf(stored_hash)
    print("  [{}] workfactor={}  cores={}  words={:,}".format(
        username, wf, num_cores, len(wordlist)))
    start = time.time()
    result = None
    with mp.Pool(num_cores) as pool:
        for found in pool.imap_unordered(worker, chunks, chunksize=1):
            if found is not None:
                result = found
                pool.terminate()
                break
    return result, time.time() - start


def main():
    parser = argparse.ArgumentParser(description="bcrypt dictionary cracker")
    parser.add_argument('--shadow', default='shadow.txt')
    parser.add_argument('--users', nargs='+', default=None)
    parser.add_argument('--wf-max', type=int, default=99)
    parser.add_argument('--cores', type=int, default=mp.cpu_count())
    args = parser.parse_args()

    print("\n" + "="*60)
    print("TASK 2: bcrypt Dictionary Cracker")
    print("="*60)
    print("  Cores: {}  WF max: {}\n".format(args.cores, args.wf_max))

    print("  Loading NLTK wordlist...", end=' ')
    sys.stdout.flush()
    wordlist = build_wordlist()
    print("{:,} words".format(len(wordlist)))

    shadow = parse_shadow(args.shadow)
    targets = args.users if args.users else list(shadow.keys())
    targets = [u for u in targets if u in shadow]
    targets = [u for u in targets if get_wf(shadow[u]) <= args.wf_max]

    if not targets:
        print("No matching users. Adjust --users or --wf-max.")
        sys.exit(0)

    print("  Cracking: {}\n".format(', '.join(targets)))

    results = []
    for username in targets:
        print("  Cracking {}...".format(username))
        pw, elapsed = crack_user(username, shadow[username], wordlist, args.cores)
        status = "'{}'".format(pw) if pw else "NOT FOUND"
        print("  -> {}  ({:.1f}s)\n".format(status, elapsed))
        results.append((username, pw, elapsed))

    print("\n" + "="*60)
    print("RESULTS")
    print("="*60)
    print("  {:<12}  {:<16}  {:>10}".format("User", "Password", "Time (s)"))
    print("  " + "-"*42)
    for username, pw, elapsed in results:
        print("  {:<12}  {:<16}  {:>10.1f}".format(
            username, pw if pw else "NOT FOUND", elapsed))


if __name__ == '__main__':
    mp.freeze_support()
    main()
