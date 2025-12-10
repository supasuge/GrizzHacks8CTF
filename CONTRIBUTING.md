# Contributing to GrizzHacks 8 CTF

Thanks for helping build challenges, you noble chaos engineer.

Before submitting **anything**, you *must* follow the repo rules — not because we’re authoritarian, but because merging broken challenges causes group-wide suffering.

---

## 🪜 Branch Naming

Every challenge lives on its own branch:

```

<category>/<challenge-name>

```

Examples:

```

crypto/LostLatticeParadise
pwn/stack-slapper
misc/QRNightmare

```

## Creating a new challenge

Create a branch as described

1. Clone the repository

```bash
git clone https://github.com/cyberOU/Grizzhacks8-CTF
cd Grizzhacks8-CTF
```

2. Make the a new branch for the challenge

```bash
git checkout -b <category>/<challenge-name>
```

3. After creating the challenges, go to the root directory and run

```bash
git add .
git commit -m "Add initial challenge for <challenge-name>
git push -u origin <category>/<chaallenge-name>
```

4. Open a Pull Request once all changes are final, and handout is ready (if any)

- Now hold your breath as we prey to the almighty merge gods no for no errors

---

## 🧱 Folder Rules (The Sacred Architecture)

When adding a new challenge, make sure you seperate your challenge files etc into three folders (`build`, `dist`, `solution`)

```
GrizzCTF-8/Crypto/Exhibit-A » tree
.
├── README.md
├── build
│   ├── Dockerfile
│   └── requirements.txt
├── dist
│   └── ubuku.py
└── solution
    ├── README.md
    └── solve.py
4 directories, 6 files
```

---

## Flag Format

Every flag MUST follow:

```
GrizzCTF{something_here}
```

---

## 🧪 Challenge Submission Checklist

- Challenge runs **inside Docker**
- Challenge works OUTSIDE Docker (optional but nice)
- `dist/` contains only intended handout files
- Someone ELSE tests your challenge
- The writeup explains the intended solution
- Your branch merges cleanly

---

## 🧯 Creating Player Handouts

From inside your challenge directory:

```bash
tar -czvf <challenge-name>-handout.tar.gz dist/
# this will be the handout for the participants
```

---
