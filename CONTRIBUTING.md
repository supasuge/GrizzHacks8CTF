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

---

## 🧱 Folder Rules (The Sacred Architecture)

When adding a new challenge, your folder MUST look like this:

```

CategoryName/
ChallengeName/
README.md
build/
Dockerfile
requirements.txt
dist/
solution/
solve.py
README.md

```

### Why so strict?
Because when the repo gets big, chaos spreads faster than a buffer overflow.

---

## 🏷 Flag Format

Every flag MUST follow:

```

GrizzCTF{something_here}

```

If your flag doesn’t follow this, your challenge goes to CTF jail.

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

```

tar -czvf <challenge-name>-handout.tar.gz dist/

```

Upload that to CTFd. Not your entire folder. Not your build environment.  
Just the handout.
```

---

# ✅ **3. NEW TESTING.md (HUMAN VERSION)**

```md
# Challenge Testing Guide

Congratulations, you finished a challenge.  
Now we find out whether it actually works or if you just hallucinated success.

---

## 1️⃣ Build Test (Does it even compile?)

```bash
cd category/challenge/build
docker build -t ghx8-test .
```


If Docker screams, YOU fix it — not the person reviewing your PR.

---

## 2️⃣ Run Test

Make sure:

- The container starts
- The challenge behaves correctly
- Ports are exposed properly
- No flags leak like a broken faucet

---

## 3️⃣ Solver Test

Run your solution:

- Does it solve the challenge?
- Consistently?
- Without relying on undefined behavior?
- Without requiring a blood sacrifice?

---

## 4️⃣ Dist Sanity Check

Ensure:

- No source code leaks in `dist/`
- No flags leak
- No credentials leak
- No leftover dev junk (test files, logs, compiled binaries)

If players can accidentally solve it by reading your mistakes, that’s on you.
