# CPE-321 — Cryptographic Hash Functions Lab

## Quick Start

```bash
git clone <your-repo-url>
cd cpe321-hash-lab
chmod +x run.sh
./run.sh demo        # task1 + crack wf=8 users (fast, good for demo)
```

## All Modes

| Command | What it does |
|---|---|
| `./run.sh demo` | Task 1 + crack Bilbo/Gandalf/Thorin (wf=8, ~few min) |
| `./run.sh task1` | SHA256 hashing, avalanche effect, collision graphs only |
| `./run.sh fast` | Crack only workfactor ≤ 8 users |
| `./run.sh task2` | Crack **all** users (warning: wf=12/13 takes many hours) |

## Running on a stronger machine (recommended for task2)

```bash
# SSH into a remote machine, clone, and run full crack
git clone <your-repo-url>
cd cpe321-hash-lab
chmod +x run.sh
./run.sh task2       # uses all available CPU cores automatically
```

## Manual usage

```bash
pip install -r requirements.txt

# Task 1 only
python task1.py

# Crack specific users
python task2.py --users Bilbo Gandalf Thorin

# Crack up to workfactor 10, using 16 cores
python task2.py --wf-max 10 --cores 16

# Crack everyone
python task2.py
```

## Expected runtimes (M1 MacBook Air, 1 core)

| Workfactor | ms/hash | ~time for 135k words |
|---|---|---|
| 8  | 30 ms  | ~68 min |
| 9  | 60 ms  | ~135 min |
| 10 | 110 ms | ~4.1 hrs |
| 11 | 220 ms | ~8.25 hrs |
| 12 | 420 ms | ~15.75 hrs |
| 13 | 840 ms | ~31.5 hrs |

With N cores, divide the above by N. 10 cores → wf=8 in ~7 min.

## Files

```
.
├── run.sh          # one-command runner
├── task1.py        # SHA256 exploration + collision graphs
├── task2.py        # bcrypt dictionary cracker
├── shadow.txt      # shadow file with 15 users to crack
└── requirements.txt
```
