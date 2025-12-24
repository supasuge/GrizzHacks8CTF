# GrizzHacks8 Official CTF repository

## Testing

## Contributing

To create a challenge, simply use the bash script to rename the challenge repo then add your challenge as you please. Try to maintain a similar structure to other challenges to avoid potential hiccups during deployment.

### Adding challenges

1. Clone locally
```bash
git clone https://github.com/cyberOU/Grizzhacks8-CTF
cd Grizzhacks8-CTF
git pull origin main # pull any changes if present
```
1.1. **Verify**

```bash
git remote -v
# Expected result
origin  https://github.com/cyberOU/Grizzhacks8-CTF (fetch)
origin  https://github.com/cyberOU/Grizzhacks8-CTF (push)
```
If the remote is not configured, add it:

HTTPS (easier for beginners, requires Personal Access Token):

```bash
git remote add origin https://github.com/cyberOU/Grizzhacks8-CTF.git
```

**SSH**

```bash
git remote add origin git@github.com:cyberOU/Grizzhacks8-CTF.git
```

To switch between the two if needed:

```bash
git remote set-url origin https://github.com/cyberOU/Grizzhacks8-CTF
# or if you have SSH enabled and setup
git remote set-url origin git@github.com:cyberOU/GrizzHacks8-CTF.git
```

2. Create a new branch for the challenge in the format: `<category>/<challenge-name>`

```bash
git checkout -b challenge/crypto/rsa-madness # examle challenge name
```

```bash
./new-chal.sh rename -c <category> -old <old_name> -new <new_name>
```
3. **Create your challenge using the provided script**
```bash
   ./new-chal.sh rename -c  -old  -new 
``` 
- **Categories**: `web`, `crypto`, `forensics`, `pwn`, `misc`, `osint`
   
**Example**:

```bash
   ./new-chal.sh rename -c crypto -old challenge3 -new rsa-madness
```

4. **Develop your challenge**
   - Add challenge files, source code, and solutions to your challenge directory
   - Maintain similar structure to existing challenges:
```
     <category>/<challenge-name>/
     ├── README.md          # Challenge description and writeup
     ├── challenge/         # Files given to participants
     ├── solution/          # Solution scripts and writeup
     ├── handout/            # Deployment files (if applicable)
     └── flag.txt           # The flag in Grizz{...} format
```

PLEASE zip/compress the handout files unless it's a singular file just to conserve server resources.

> *not required*
```bash
zip dir-name.zip challenge/ -r # recursively zips challenge + all files/subdirs
zip chal-name.zip out.txt util.py # compress two files into chal-name.zip

# TAR IS PREFERRED (better compression algo).
tar -cvJf archive.tar.xz directory_name/ # create archive of directory
# to extract archive
tar -xvJf archive.tar.xz
```
5. **Create a challenge README**
   Your challenge should include a `README.md` with:
   - Challenge title and category
   - Point value
   - Description/story
   - Author name
   - Hints (if applicable)
   - Solution writeup (can be brief)
Example:

```md
# Challenge name
- **Author**: Tony Stark
- **Category**: Being an aboslute unit
- **Difficulty**: { Easy | Medium | Hard }
- **Hints**: (if applicable)

## Challenge Description

## Build instructions

## Deploy instructions

## Handout files (if applicable)


```

6. **Test your challenge**
   - Ensure the challenge is solvable
   - Verify the flag format is correct (`GRIZZ{...}`)
   - Test deployment files if applicable

7. **Commit and push your changes**
```bash
git add .
git commit -m "Add / challenge"

git push origin <challenge>/<chal-name> # Branch created here.
# will merge at later time.
```

#### Flag Format

```
Grizz{...}
```

Note that the folder's were created using a script and we don't need to have this many challenges.
