# ECBeast

- Category: Crypto
- Difficulty: Easy
- Author: [supasuge](https://github.com/supasuge) | Evan Pardon


## Build

To build the docker container and prepare to be uploaded to CTFd:

```bash
docker build -t ecbeast:latest .
# or optionally just run:
./build.sh
```

## Run the challenge

```bash
docker run --rm -p 5337:5337 ecbeast:latest
# or optionally just run:
./run.sh
```

## Handout

```bash
cd ECBeast/handout
tar -cJf ecbeast-handout.tar.xz chal.py flag.example.txt supervisord.conf Dockerfile
# output
ecbeast-handout.tar.xz
|
|> chal.py
|> flag.example.txt (for local testing)
|> Dockerfile       (for local testing)
|> supervisord.conf (for local testing)
```

### Flag format

```
GRIZZ{...}
```

Actual:

```
GRIZZ{n0_1v_n0_s3cur1ty_3cb_l0l}
```
