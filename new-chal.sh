#!/usr/bin/env bash
set -euo pipefail

categories=("Pwn" "Crypto" "Web" "Forensics" "Misc" "OSINT")
num_challenges=5

print_usage() {
    echo "Usage:"
    echo "  ./new-chal.sh init"
    echo "  ./new-chal.sh rename -c <category> -old <old_name> -new <new_name>"
}

# ============================================================
# RENAME MODE
# ============================================================
if [[ "${1:-}" == "rename" ]]; then
    shift
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -c|--category) category="$2"; shift ;;
            -old) old="$2"; shift ;;
            -new) new="$2"; shift ;;
        esac
        shift
    done

    if [[ -z "${category:-}" || -z "${old:-}" || -z "${new:-}" ]]; then
        print_usage
        exit 1
    fi

    if [[ ! -d "$category/$old" ]]; then
        echo "[-] Error: $category/$old does not exist."
        exit 1
    fi

    mv "$category/$old" "$category/$new"
    echo "[✔] Renamed $category/$old → $category/$new"
    exit 0
fi

# ============================================================
# INIT MODE
# ============================================================
if [[ "${1:-}" != "init" ]]; then
    print_usage
    exit 1
fi

#echo "[+] Initializing GrizzHacks 8 CTF repository..."
#echo "[+] Building directory structure... Brace yourself."

# ROOT FILES --------------------------------------------------
#cat > README.md <<'EOF'
# (same rewritten README as above)
#EOF

#cat > CONTRIBUTING.md <<'EOF'
# (same rewritten CONTRIBUTING.md as above)
#EOF

#cat > TESTING.md <<'EOF'
# (same rewritten TESTING.md as above)
#EOF

#echo "__pycache__/ 
#*.pyc
#dist/*.zip
#solution/*.zip
#.env
#.DS_Store" > .gitignore

#cat > LICENSE <<'EOF'
#MIT License
#Copyright ...
#EOF

# CATEGORY GENERATION -----------------------------------------
#for category in "${categories[@]}"; do
#    mkdir -p "$category"
#    echo "# ${category} Challenges" > "$category/README.md"

    #for i in $(seq 1 $num_challenges); do
     #   chal="$category/challenge$i"
      #  mkdir -p "$chal"/{build,dist,solution}

#cat > "$chal/README.md" <<EOF
# Challenge-$i
#- **Author:** (your name)
#- **Category:** $category
#- **Difficulty:** {Easy | Medium | Hard | Expert}
#- **Flag Format:** \`GrizzCTF{...}\`

## Description


## Build Instructions
#\`\`\`
#cd build
#docker build -t ${category,,}-challenge$i .
#\`\`\`

## Running
#Document how to run the challenge here.
#EOF

#cat > "$chal/build/Dockerfile" <<EOF
#FROM python:3.11-slim
#WORKDIR /app
#COPY . .
#RUN pip install -r requirements.txt || true
#CMD ["bash"]
#EOF

#echo "# Add Python dependencies here" > "$chal/build/requirements.txt"

#cat > "$chal/solution/solve.py" <<EOF
##!/usr/bin/env python3

#def solve():
#    print("Solve script for $category challenge $i goes here.")

#if __name__ == "__main__":
#    solve()
#EOF

#echo "# Solution writeup here" > "$chal/solution/README.md"

#touch "$chal/dist/.gitkeep"

#    done
#done

#echo "[✔] Repo initialization complete. Go make challenges players will cry over."
#exit 0
