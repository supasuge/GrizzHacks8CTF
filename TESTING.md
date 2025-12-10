# Challenge Testing Guide

> Note: Im tired, and hungry and my sarcasm is gettin wild rn and im lovin it. It's all jokes n stuff so if u get offended kindly click away as that is not my problem. Words on a screen omg OWWWWWWWW. Right? k love u too.

**Congratulations**, you finished a challenge! Now what the hell am I supposed to do?

Well... Now we find out whether it actually works or if you just hallucinated success. I often err' on the side of controlled "Absolutely no clue what is happening here but some research paper said it would work and it did so im basically (disabled) coding jesus...". Fake it til' you make it yo

---

## 1️⃣ Build Test (Does it even compile?): Make sure to use a common docker image like ubuntu or whatever you developed the challenge on so no issues during build

```bash
cd category/challenge/build
docker build -t ur-mums-dippin-dotz .
# some banana split dippin dotz would go fuckin nuts rn hooooollllyyyyyyyyy... 
# this should be our CTF prize for winning team.
# cool item worth a lotta money? nah... Gimme dat banana split pronto or imma shit... wait
# .... sit! slipped...
```

If Docker screams, (that sucks lmao). Just spit on ur hand and slap tf out of it, show em who's papa. In all seriousness, sadly: YOU fix it — not the person reviewing your PR. If I didnt write your challenge, I'm not going to spend the time to fix it unless it's trivial. All love, but time is money and crypto challenges take a long time to get right and verify so until I finish those I dont want to make false promises. If you can't figure out how to fix it, well for one; god be with you (kidding, docker hates me too)... and two, just shoot me a text and I will gladly help as much as I or anyone else is able to. Docker is a love hate relationship........ Usually hate. But it does the thing, win some ya lose some eh?

---

## 2️⃣ Run Test

- Self explanatory but here we go anyways ffs

Make sure:

- The container starts/runs without error
- The challenge behaves correctly + is supervised via supervisord to restart the container in case of a fatal error.
- Ports are exposed properly and can be properly connected to
- No flags leak like a broken faucet

---

## 3️⃣ Solver Test

- Also Self-explanatory but here we go anyways ffs, just dont hand in an unsolveable challenge or it would look worse then turning in "Hello World" as a hard challenge. I have done this on accident and somehow no one noticed myself included until competition was over... WHOOOOOOOOPPPPPSS. Dont be like me lol. That one challenge made/breaked the difference of two teams winning or losing, so was definitely tough to watch knowing I very simply uploaded the wrong file.

Run your solution:

- Does it solve the challenge? Wouldnt be much of a solution if it didn't eh?
- Consistently? This is subjective... Crypto chal's will likely be heavily probability based and therefore nearly impossible to guarantee a single specific outcome
- Without relying on undefined behavior? Make sure you don't have undefined behavior/logic that could be used to further manipulate the program somehow.
- Without requiring a blood sacrifice? I cry everytime I read a lattice cryptanalysis paper... GPT did NOT have to call me out like that smh asshole
- Any unintended solutions? Try to avoid these, though it will happen sometimes. If it's a unique and creative solution then extra points for being a beast.

---

## 4️⃣ Dist Sanity Check

Ensure:

- No source code leaks in `dist/`
- No flags leak
- No credentials leak
- No leftover dev junk (test files, logs, compiled binaries)

If players can accidentally solve it by reading your mistakes, that’s on you.

**Don't be that guy/gal... Take your time and have fun!!!**