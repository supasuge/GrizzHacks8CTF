# Tropic Like It's Hot

- **Category:** Crypto
- **Author:** [supasuge](https://github.com/supasuge) | [Evan Pardon](https://linkedin.com/in/evan-pardon) | [supasuge.com](https://supasuge.com)
- **Difficulty:** Hard
- **Points:** 450
- **Event:** GrizzHacks 8 CTF

## Challenge Inspiration

- [Structural Collapse of the Amutha-Perumal Scheme Based on Duo Circulant Matrices](https://eprint.iacr.org/2026/354) — Chavhan & Chaudhari, ePrint 2026/354

---

## Overview & History

```
In 2005, Stickel proposed a key exchange protocol based on the difficulty of the dis-
crete logarithm problem in the group of invertible matrices over a finite field. However,
Shpilrain later demonstrated that the protocol is insecure: an attacker can recover the se-
cret exponents using linear algebra techniques, exploiting the invertibility of the underlying
matrices. This attack highlighted the need for alternative algebraic platforms that lack
invertible elements and thus resist such classical cryptanalytic approaches. Tropical cryp-
tography emerged as a promising direction following the work of Grigoriev and Shpilrain,
who proposed the first key exchange protocol based on tropical polynomials and the max-plus
semiring. The tropical semiring (R ∪ {−∞}, ⊕, ⊙), where a ⊕ b = max(a, b) and a ⊙ b =
a + b, offers a fundamentally different algebraic structure.
```
> [Source (Section 1)](https://eprint.iacr.org/2026/354.pdf)

Against this backdrop, Amutha and Perumal proposed a two-party key exchange protocol based on $\alpha$-$v$-$w$-duo circulant matrices over the max-plus semiring. The protocol introduces a commutative subset of matrices derived from $w$-circulant matrices with specific modifications, designed to enable efficient key generation while withstanding known tropical attacks. The authors claimed that their protocol resists all prevalent attacks on tropical key exchange systems and that it's underpinned by the NP-hardness of solving systems of *non-linear* equations over the tropical semiring.

It was proposed to integrate the protocol into IoT environments due to its efficiency. However, this challenge demonstrates the attack described in the aforementioned research paper — a complete cryptanalysis of the Amutha-Perumal protocol revealing a severe affine structure on all secret matrices. Every matrix in the protocol is of the form $a + C$, where $a$ is a single secret integer and $C$ is a fixed matrix determined solely by public parameters. This leads to a structural collapse:

- The public messages satisfy $K_a = (a_1 + b_1) + M$ and $K_b = (a_2 + b_2) + M$
- The session key simplifies to $K = (a_1 + a_2 + b_1 + b_2) + W$ with $W$ publicly computable
- An eavesdropper can recover the shared secret in constant time after a one-time precomputation of $O(m^3)$

This attack is deterministic, succeeds with a probability of 1 for all parameter choices, and requires only passive observation of the exchanged messages.

---

## The Challenge

We're given "intercepted" traffic from a proprietary IoT key exchange protocol based on $\alpha$-$v$-$w$-duo circulant matrices over the **max-plus tropical semiring**.

The challenge provides all public parameters, both exchanged messages, and an AES-CBC encrypted flag. Our task is to recover the shared session key.

The attack exploits a fundamental structural flaw within the duo circulant construction: every secret matrix is an **affine function** of a single integer parameter. This means the entire multi-dimensional matrix "secret" collapses to a scalar, and that scalar can be read directly from any entry of the intercepted public message.

---

## Background: Algebraic Foundations

Before diving into the protocol and the attack, we need to establish several algebraic concepts. If you're already comfortable with semirings and tropical algebra, skip to [The Amutha-Perumal Key Exchange Protocol](#the-amutha-perumal-key-exchange-protocol).

---

### Semirings

A **semiring** is an algebraic structure $(S, \oplus, \odot)$ that satisfies all the axioms of a ring, **except** that additive inverses are not required. Formally:

1. $(S, \oplus)$ is a commutative monoid with identity element $0_S$
2. $(S, \odot)$ is a monoid with identity element $1_S$
3. Multiplication distributes over addition from both sides:

$$a \odot (b \oplus c) = (a \odot b) \oplus (a \odot c)$$

$$(b \oplus c) \odot a = (b \odot a) \oplus (c \odot a)$$

4. The additive identity annihilates under multiplication: $0_S \odot a = a \odot 0_S = 0_S$

> 💡 **Intuition:** A semiring is like a ring where you can add and multiply, but you **cannot subtract**. The natural numbers $(\mathbb{N}_0, +, \times)$ are the most familiar example.

Traditional number-theoretic cryptography operates over rings and fields (integers mod $p$, elliptic curve groups). Tropical cryptography replaces these with semirings where the operations have radically different computational properties — the hope is that certain problems (like matrix factorization) become harder in this exotic setting.

---

### Idempotent Semirings

A semiring is **idempotent** if the addition operation satisfies:

$$a \oplus a = a \quad \forall\, a \in S$$

This is a very unusual property. In ordinary arithmetic, $3 + 3 = 6 \neq 3$. But in an idempotent semiring, "adding" an element to itself does not change it.

> 📌 **Canonical Example:** The operation $\max(a, a) = a$ is idempotent. So is $\min(a, a) = a$.

Every **tropical semiring** is idempotent, because tropical addition is either $\max$ or $\min$.

The idempotent property has deep consequences: there is no notion of "cancellation" or "subtraction" within the semiring itself. You cannot recover $b$ from $a \oplus b = c$ in general, because $\oplus = \max$ is a lossy operation — it discards the smaller operand. This is part of what makes tropical algebra appealing for cryptographic purposes (in theory).

---

### The Max-Plus Tropical Semiring

The **max-plus semiring** (also called the **tropical semiring** in the max-plus convention) is the algebraic structure:

$$(\mathbb{Z}_{\max},\; \oplus,\; \odot) \quad \text{where} \quad \mathbb{Z}_{\max} = \mathbb{Z} \cup \lbrace-\infty\rbrace$$

Let $\mathbb{Z}$ denote the set of integers and define $\mathbb{Z}_{\max} = \mathbb{Z} \cup \lbrace -\infty \rbrace$. The operations are:

$$a \oplus b = \max(a, b)$$

$$a \odot b = a + b$$

> ⚠️ **Naming Confusion**
> There are **two** competing conventions in tropical mathematics:
> - **Max-plus** (or "max-tropical"): $\oplus = \max$, $\odot = +$. Used in this protocol.
> - **Min-plus** (or "min-tropical"): $\oplus = \min$, $\odot = +$. Common in optimization.
>
> The Amutha-Perumal protocol uses the **max-plus** convention.

---

**Identity elements:**

| Operation | Symbol | Identity | Reason |
|-----------|--------|----------|--------|
| Tropical addition | $\oplus = \max$ | $-\infty$ | $\max(a, -\infty) = a$ |
| Tropical multiplication | $\odot = +$ | $0$ | $a + 0 = a$ |

---

**Verification of semiring axioms:**

- [x] *Commutativity of $\oplus$:* $\max(a, b) = \max(b, a)$
- [x] *Associativity of $\oplus$:* $\max(\max(a, b), c) = \max(a, \max(b, c))$
- [x] *Associativity of $\odot$:* $(a + b) + c = a + (b + c)$
- [x] *Distributivity:* $a + \max(b, c) = \max(a + b, a + c)$
- [x] *Annihilation:* $a + (-\infty) = -\infty$

> 📝 **Why "Tropical"?** The name was coined by French mathematicians in honor of Brazilian mathematician Imre Simon, who pioneered this area. It refers to his tropical homeland, not to any property of the algebra itself.

---

### Tropical Matrix Multiplication

Tropical operations extend naturally to matrices. For $A \in \mathbb{Z}_{\max}^{m \times p}$ and $B \in \mathbb{Z}_{\max}^{p \times n}$, the **tropical matrix product** is:

$$(A \odot B)_{ij} = \bigoplus_{k=1}^{p} (A_{ik} \odot B_{kj}) = \max_{k=1}^{p} \lbrace A_{ik} + B_{kj} \rbrace$$

This looks exactly like ordinary matrix multiplication, but with $\max$ replacing $\sum$ and $+$ replacing $\times$.

**Concrete Computation:**

Let

$$A = \begin{pmatrix} 3 & 1 \\\ 2 & 4 \end{pmatrix} \quad \text{and} \quad B = \begin{pmatrix} 0 & 5 \\\ 1 & 2 \end{pmatrix}$$

$$(A \odot B)_{11} = \max(3+0,\; 1+1) = \max(3, 2) = 3$$

$$(A \odot B)_{12} = \max(3+5,\; 1+2) = \max(8, 3) = 8$$

$$(A \odot B)_{21} = \max(2+0,\; 4+1) = \max(2, 5) = 5$$

$$(A \odot B)_{22} = \max(2+5,\; 4+2) = \max(7, 6) = 7$$

$$A \odot B = \begin{pmatrix} 3 & 8 \\\ 5 & 7 \end{pmatrix}$$

**Key properties:**
- Tropical matrix multiplication is **associative**: $(A \odot B) \odot C = A \odot (B \odot C)$
- It is generally **not commutative**: $A \odot B \neq B \odot A$
- The identity matrix has $0$ on the diagonal and $-\infty$ elsewhere

The non-commutativity of general tropical matrix multiplication is what makes Stickel-type key exchange protocols possible — the security is supposed to rest on the difficulty of factoring $A \odot X \odot B$ back into $A$ and $B$.

---

### The Scalar Shift Lemma (Critical for the Attack)

This property is the linchpin of the entire attack, so we state and prove it carefully.

> **Lemma (Scalar Pass-Through).** If $s \in \mathbb{Z}$ is a scalar and $A, B$ are tropical matrices, then:
>
> $$(s + A) \odot B = s + (A \odot B)$$
>
> where $s + A$ denotes adding $s$ to **every entry** of $A$ (i.e., $(s + A)_{ij} = s + A_{ij}$).

**Proof:**

$$\bigl((s + A) \odot B\bigr)_{ij} = \max_{k} \lbrace(s + A_{ik}) + B_{kj}\rbrace$$

$$= \max_{k} \lbrace s + A_{ik} + B_{kj}\rbrace$$

$$= s + \max_{k} \lbrace A_{ik} + B_{kj}\rbrace$$

$$= s + (A \odot B)_{ij} \quad \blacksquare$$

The third step uses the fact that adding a constant to every element inside a $\max$ is equivalent to adding it outside: $\max(s + x_1, s + x_2, \ldots) = s + \max(x_1, x_2, \ldots)$.

By the same argument, $A \odot (s + B) = s + (A \odot B)$, and for a chain of products:

$$(s + A) \odot X \odot (t + B) = (s + t) + (A \odot X \odot B)$$

> 🚨 **Why This Is Devastating:** If a cryptographic protocol uses secret matrices that are just **scalar shifts** of publicly known matrices, then the scalar passes through every tropical product unchanged. The "secret" contributes nothing structural — it's a uniform bias that can be trivially subtracted off.

---

### Circulant Matrices

A **circulant matrix** is a square matrix where each row is a cyclic right-shift of the row above it. For a standard circulant with first row $(c_0, c_1, \ldots, c_{n-1})$:

$$C = \begin{pmatrix} c_0 & c_1 & c_2 & \cdots & c_{n-1} \\\ c_{n-1} & c_0 & c_1 & \cdots & c_{n-2} \\\ c_{n-2} & c_{n-1} & c_0 & \cdots & c_{n-3} \\\ \vdots & \vdots & \vdots & \ddots & \vdots \\\ c_1 & c_2 & c_3 & \cdots & c_0 \end{pmatrix}$$

Circulant matrices have the important property that **they commute under ordinary matrix multiplication**: $C_1 \cdot C_2 = C_2 \cdot C_1$. This is because they are all simultaneously diagonalizable by the DFT matrix.

A **$w$-circulant matrix** generalizes this: when elements "wrap around" during the cyclic shift, they get an additive offset of $w$ applied. In the tropical (max-plus) setting, this means:

$$M_{ij} = r_{(j-i) \bmod m} + w \cdot \mathbb{1}[j < i]$$

where $\mathbb{1}[j < i]$ is the indicator function for a wrap-around occurring.

> ℹ️ **Why Circulants in Cryptography?** The commutative subsets formed by families of circulant matrices are what make the key exchange work. Without commutativity, Alice and Bob would not arrive at the same shared key. The protocol needs $A_1 \odot A_2 = A_2 \odot A_1$ — which is guaranteed when both matrices belong to the same circulant family.

---

### The Duo Circulant Construction

The Amutha-Perumal protocol defines **$\alpha$-$v$-$w$-duo circulant matrices**. These are $w$-circulant matrices whose first row is generated by a specific recurrence.

Given public parameters $(\alpha, v, w, m)$ and a secret first-row parameter $p_1 \in \mathbb{Z}$:

$$r_1 = p_1$$

$$r_i = \max(\alpha + r_{i-1},\; v) \quad \text{for } i = 2, 3, \ldots, m$$

This recurrence generates the first row $\mathbf{r} = (r_1, r_2, \ldots, r_m)$, which is then used to construct the full $m \times m$ $w$-circulant matrix.

Two families are defined by choosing different "floor" parameters:

| Family | Floor Parameter | Notation | Used By |
|--------|----------------|----------|---------|
| $\mathcal{A}_v$ | $v$ | $A(p_1)$ | Both devices (left-action) |
| $\mathcal{B}_c$ | $c$ | $B(p_1)$ | Both devices (right-action) |

> ⚠️ **Commutativity Properties**
> The protocol's correctness relies on:
> 1. **Intra-class commutativity:** For any $A, A' \in \mathcal{A}_v$: $A \odot A' = A' \odot A$
> 2. **Intra-class commutativity:** For any $B, B' \in \mathcal{B}_c$: $B \odot B' = B' \odot B$
>
> These hold because all matrices within each family share the same $w$-circulant structure.

---

## The Amutha-Perumal Key Exchange Protocol

Now we can describe the full protocol. It follows the **Stickel-type** two-sided action paradigm — a common template in non-commutative key exchange.

### Public Parameters (known to everyone, including the attacker)

$$m,\; \alpha,\; w,\; v,\; c \in \mathbb{Z} \qquad X \in \mathbb{Z}^{m \times m} \;\text{(random public matrix)}$$

### Key Generation

**Device 1 (Alice):**
1. Choose secret integers $a_1, b_1 \in \mathbb{Z}$
2. Build $A_1 \in \mathcal{A}_v$ using the recurrence with $p_1 = a_1$
3. Build $B_1 \in \mathcal{B}_c$ using the recurrence with $p_1 = b_1$
4. Compute and transmit: $K_a = A_1 \odot X \odot B_1$

**Device 2 (Bob):**
1. Choose secret integers $a_2, b_2 \in \mathbb{Z}$
2. Build $A_2 \in \mathcal{A}_v$ using the recurrence with $p_1 = a_2$
3. Build $B_2 \in \mathcal{B}_c$ using the recurrence with $p_1 = b_2$
4. Compute and transmit: $K_b = A_2 \odot X \odot B_2$

### Key Agreement

Each device computes the shared key using the other's public message:

$$K_{\text{Alice}} = A_1 \odot K_b \odot B_1 = A_1 \odot (A_2 \odot X \odot B_2) \odot B_1$$

$$K_{\text{Bob}} = A_2 \odot K_a \odot B_2 = A_2 \odot (A_1 \odot X \odot B_1) \odot B_2$$

By associativity and the intra-class commutativity of $\mathcal{A}_v$ and $\mathcal{B}_c$:

$$K = A_1 \odot A_2 \odot X \odot B_1 \odot B_2 = A_2 \odot A_1 \odot X \odot B_2 \odot B_1$$

Both devices arrive at the same $K$. An eavesdropper sees $K_a$ and $K_b$ but supposedly cannot extract $A_1, B_1, A_2, B_2$ from them.

<details>
<summary><strong>❓ What Is Stickel's Protocol?</strong></summary>

The Amutha-Perumal scheme is a tropical instantiation of **Stickel's key exchange** (2005), which generalizes Diffie-Hellman to non-abelian semigroups. In classical Stickel, Alice sends $A \cdot M \cdot B$ and Bob sends $C \cdot M \cdot D$, where $A, B$ commute with $C, D$ respectively. The shared key is $A \cdot C \cdot M \cdot B \cdot D$. The security relies on the difficulty of decomposing the public messages back into their factors.

</details>

---

## The Vulnerability: Affine Structural Collapse

This is the heart of the cryptanalysis. We show that the duo circulant construction fatally over-constrains every secret matrix to a single scalar parameter.

### Lemma 3.1 — Affine Parameterization

> **Lemma (Affine Collapse).** For any $\alpha$-$v$-$w$-duo circulant matrix $A(p_1)$ built with first-row parameter $p_1$, there exists a **constant matrix** $C$ (depending only on $\alpha, v, w, m$ — all public) such that:
>
> $$A(p_1) = p_1 + C$$
>
> where $p_1 + C$ denotes adding the scalar $p_1$ to every entry of $C$, and $C = A(0)$ is the matrix obtained by setting $p_1 = 0$ in the recurrence.

**Full Proof:**

Define $c_i$ as the row entries when $p_1 = 0$:

$$c_1 = 0, \quad c_i = \max(\alpha + c_{i-1},\; v) \quad \text{for } i \geq 2$$

Now consider the general case. We claim $r_i = p_1 + c_i$ for all $i$. Proceed by **strong induction**.

**Base case** ($i = 1$): $r_1 = p_1 = p_1 + 0 = p_1 + c_1$ ✓

**Inductive step:** Assume $r_{i-1} = p_1 + c_{i-1}$. Then:

$$r_i = \max(\alpha + r_{i-1},\; v) = \max(\alpha + p_1 + c_{i-1},\; v)$$

We need this to equal $p_1 + c_i = p_1 + \max(\alpha + c_{i-1},\; v)$.

Using the identity $\max(p_1 + x,\; y) = p_1 + \max(x,\; y - p_1)$, we get:

$$r_i = p_1 + \max(\alpha + c_{i-1},\; v - p_1)$$

This equals $p_1 + c_i$ **if and only if** $v - p_1 \leq \alpha + c_{i-1}$ for all $i$, i.e.:

$$p_1 \geq v - \alpha - c_{i-1} \quad \forall\, i$$

Since $c_i$ is non-decreasing (it grows by at least $\alpha > 0$ at each step, or is floored at $v$), the tightest constraint comes from $i = 2$ where $c_1 = 0$:

$$p_1 \geq v - \alpha$$

For the challenge parameters ($\alpha = 54$, $v = -260$), this requires $p_1 \geq -314$. Since secrets are drawn from $[-10^5, 10^5]$, this is satisfied with overwhelming probability — in fact, it holds for **all** 400 test instances in the paper.

> ⚠️ **Generality:** Even when $p_1 < v - \alpha$ (extremely negative secrets), the affine relationship $r_i = p_1 + c_i$ still holds for all indices $i$ beyond a small threshold, because the recurrence "catches up" to the linear regime. In practice, for typical parameter choices, it holds for **all** indices simultaneously.

Since the $w$-circulant structure only adds $w$ to wrapped entries (a fixed offset independent of $p_1$), the full matrix satisfies:

$$A(p_1)_{ij} = r_{(j-i) \bmod m} + w \cdot \mathbb{1}[j < i] = (p_1 + c_{(j-i) \bmod m}) + w \cdot \mathbb{1}[j < i] = p_1 + C_{ij}$$

$$\therefore \quad A(p_1) = p_1 + C \quad \blacksquare$$

---

### Consequence: Collapsing the Key Exchange

Apply the affine parameterization to every secret matrix in the protocol:

$$A_1 = a_1 + C^{(A)}, \quad A_2 = a_2 + C^{(A)}, \quad B_1 = b_1 + C^{(B)}, \quad B_2 = b_2 + C^{(B)}$$

where $C^{(A)} = A(0)$ using family parameter $v$, and $C^{(B)} = B(0)$ using family parameter $c$.

**Public message $K_a$:**

$$K_a = A_1 \odot X \odot B_1 = (a_1 + C^{(A)}) \odot X \odot (b_1 + C^{(B)})$$

Applying the scalar pass-through lemma twice:

$$= a_1 + (C^{(A)} \odot X \odot (b_1 + C^{(B)}))$$

$$= a_1 + b_1 + (C^{(A)} \odot X \odot C^{(B)})$$

Define the **publicly computable base matrix**:

$$M \triangleq C^{(A)} \odot X \odot C^{(B)}$$

Then:

$$\boxed{K_a = (a_1 + b_1) + M}$$

This means every entry of $K_a$ is just the corresponding entry of $M$ shifted by the **same scalar** $a_1 + b_1$. The entire $m \times m$ public message leaks the sum of Alice's two secrets through a single entry.

Similarly: $K_b = (a_2 + b_2) + M$.

**Shared session key:**

$$K = A_1 \odot A_2 \odot X \odot B_1 \odot B_2$$

$$= (a_1 + C^{(A)}) \odot (a_2 + C^{(A)}) \odot X \odot (b_1 + C^{(B)}) \odot (b_2 + C^{(B)})$$

Grouping the left factors:

$$(a_1 + C^{(A)}) \odot (a_2 + C^{(A)}) = (a_1 + a_2) + (C^{(A)} \odot C^{(A)})$$

Define $U \triangleq C^{(A)} \odot C^{(A)}$. Similarly, define $V \triangleq C^{(B)} \odot C^{(B)}$, and:

$$W \triangleq U \odot X \odot V$$

Then:

$$\boxed{K = (a_1 + a_2 + b_1 + b_2) + W}$$

The scalar $(a_1 + b_1) + (a_2 + b_2)$ is extractable from the intercepted messages:

$$a_1 + b_1 = K_a[0,0] - M[0,0]$$

$$a_2 + b_2 = K_b[0,0] - M[0,0]$$

Therefore:

$$\boxed{K = \bigl(K_a[0,0] + K_b[0,0] - 2 \cdot M[0,0]\bigr) + W}$$

> ✅ **Everything on the right-hand side is computable from public information alone.**
> - $M = C^{(A)} \odot X \odot C^{(B)}$ — computed from public parameters
> - $W = C^{(A)} \odot C^{(A)} \odot X \odot C^{(B)} \odot C^{(B)}$ — computed from public parameters
> - $K_a[0,0]$ and $K_b[0,0]$ — read from intercepted messages

---

## The Attack Algorithm

### Pseudocode

```
Algorithm 1: Structural Collapse Attack on Amutha-Perumal Protocol
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Require: Public parameters m, α, w, v, c; public matrix X;
         intercepted messages Ka, Kb
Ensure:  Shared secret key K

─── PRECOMPUTATION PHASE (one-time) ───────────────────────────────

 1:  C_A ← BuildDuoCirculant(p1=0, α, v, w, m)     ▷ Constant matrix for A_v
 2:  C_B ← BuildDuoCirculant(p1=0, α, c, w, m)     ▷ Constant matrix for B_c
 3:  M   ← C_A ⊙ X ⊙ C_B                           ▷ Base of all public messages
 4:  U   ← C_A ⊙ C_A                                ▷ Squared left constant
 5:  V   ← C_B ⊙ C_B                                ▷ Squared right constant
 6:  W   ← U ⊙ X ⊙ V                               ▷ Base of all session keys

─── ONLINE PHASE (per intercepted session) ────────────────────────

 7:  s ← Ka[0,0] − M[0,0]                           ▷ s = a1 + b1
 8:  t ← Kb[0,0] − M[0,0]                           ▷ t = a2 + b2
 9:  K ← (s + t) + W                                ▷ Entrywise scalar addition
10:  return K
```

### Complexity Analysis

| Phase | Time Complexity | Space Complexity |
|-------|----------------|-----------------|
| Precomputation | $O(m^3)$ | $O(m^2)$ |
| Online (per session) | $O(1)$ | $O(m^2)$ |

The precomputation involves three tropical matrix multiplications (steps 3, 4-5, 6), each costing $O(m^3)$. The online phase is two subtractions and one scalar broadcast — constant time regardless of matrix dimension.

> 💡 **Comparison With Prior Work:** Buchinskiy, Kotov, and Treier (2024) also attacked Amutha-Perumal, but via **cover enumeration + linear programming** — a heuristic approach taking ~6.6 seconds for $m = 50$. The structural collapse attack takes **0.00019 seconds** for the same dimension, is deterministic, and identifies the root cause of the vulnerability.

---

## Step-by-Step Walkthrough (Challenge Instance)

### Step 1 — Parse the Intercepted Data

Load `output.txt` (JSON format) and extract:

| Parameter | Value |
|-----------|-------|
| $m$ | $6$ |
| $\alpha$ | $54$ |
| $w$ | $18$ |
| $v$ | $-260$ |
| $c$ | $-194$ |

Plus the $6 \times 6$ public matrix $X$, intercepted messages $K_a$ and $K_b$, and AES-CBC ciphertext with IV.

### Step 2 — Build Constant Matrices

Evaluate the recurrence with $p_1 = 0$:

**For $C^{(A)}$ (family $\mathcal{A}_v$, floor $= v = -260$):**

| $i$ | Computation | $r_i$ |
|-----|-------------|--------|
| $1$ | $r_1 = 0$ | $0$ |
| $2$ | $\max(54 + 0,\; -260) = \max(54, -260)$ | $54$ |
| $3$ | $\max(54 + 54,\; -260) = \max(108, -260)$ | $108$ |
| $4$ | $\max(54 + 108,\; -260) = \max(162, -260)$ | $162$ |
| $5$ | $\max(54 + 162,\; -260) = \max(216, -260)$ | $216$ |
| $6$ | $\max(54 + 216,\; -260) = \max(270, -260)$ | $270$ |

First row of $C^{(A)}$: $(0,\; 54,\; 108,\; 162,\; 216,\; 270)$

Since $\alpha + 0 = 54 > -260 = v$ right from the start, the floor parameter $v$ never activates. The row is simply $r_i = 54(i-1)$, an arithmetic progression. This is exactly why the affine collapse works here — the "floor" parameter $v$ was meant to introduce nonlinearity, but for any reasonable secret $p_1$, the term $\alpha + r_{i-1}$ dominates $v$ at every step. The $\max$ never fires its second branch.

**For $C^{(B)}$ (family $\mathcal{B}_c$, floor $= c = -194$):** Identical computation — the floor $c = -194$ is also never activated.

First row of $C^{(B)}$: $(0,\; 54,\; 108,\; 162,\; 216,\; 270)$

Then each matrix is expanded to $6 \times 6$ using the $w$-circulant structure (wraps add $w = 18$).

### Step 3 — Compute Derived Matrices

$$M = C^{(A)} \odot X \odot C^{(B)}$$

$$U = C^{(A)} \odot C^{(A)}, \quad V = C^{(B)} \odot C^{(B)}$$

$$W = U \odot X \odot V$$

All tropical matrix multiplications using $(A \odot B)_{ij} = \max_k \lbrace A_{ik} + B_{kj}\rbrace$.

### Step 4 — Extract Scalar Sums

$$s = K_a[0,0] - M[0,0] = 51408 - 1388 = 50020$$

$$t = K_b[0,0] - M[0,0] = 77817 - 1388 = 76429$$

These are the secret scalar sums: $s = a_1 + b_1$ and $t = a_2 + b_2$.

### Step 5 — Recover the Session Key

$$K_{ij} = W_{ij} + (s + t) = W_{ij} + 126449 \quad \forall\; i, j$$

### Step 6 — Derive AES Key and Decrypt

```python
key_material = ",".join(str(int(x)) for x in K.flatten())
aes_key = hashlib.sha256(key_material.encode()).digest()

cipher = AES.new(aes_key, AES.MODE_CBC, iv)
flag = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
```

---

## Implementation

The complete solve script is ~100 lines of Python with dependencies on `numpy` and `pycryptodome`.

```python
#!/usr/bin/env python3
"""Structural Collapse Attack — Solve Script"""

import json, hashlib, numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

NEG_INF = float("-inf")

def trop_mat_mul(A, B):
    """(A ⊙ B)_ij = max_k { A_ik + B_kj }"""
    m, p = A.shape; _, n = B.shape
    C = np.full((m, n), NEG_INF)
    for i in range(m):
        for j in range(n):
            for k in range(p):
                val = NEG_INF if (A[i,k] == NEG_INF or B[k,j] == NEG_INF) \
                              else A[i,k] + B[k,j]
                if val > C[i,j]: C[i,j] = val
    return C

def build_constant_matrix(alpha, v_or_c, w, m):
    """Build C = A(p1=0): the constant part of the duo circulant family."""
    row = [0] * m
    for i in range(1, m):
        row[i] = max(alpha + row[i-1], v_or_c)
    M = np.full((m, m), NEG_INF)
    for i in range(m):
        for j in range(m):
            shift = (j - i) % m
            wraps = 1 if j < i else 0
            M[i][j] = row[shift] + w * wraps
    return M.astype(float)

# ── Load data ──
with open("output.txt") as f:
    data = json.load(f)
p = data["public_params"]
X  = np.array(data["public_matrix_X"], dtype=float)
Ka = np.array(data["intercepted"]["Ka"], dtype=float)
Kb = np.array(data["intercepted"]["Kb"], dtype=float)
iv = bytes.fromhex(data["encrypted_flag"]["iv"])
ct = bytes.fromhex(data["encrypted_flag"]["ciphertext"])

# ── Precomputation ──
C_A = build_constant_matrix(p["alpha"], p["v"], p["w"], p["m"])
C_B = build_constant_matrix(p["alpha"], p["c"], p["w"], p["m"])
M = trop_mat_mul(trop_mat_mul(C_A, X), C_B)
U = trop_mat_mul(C_A, C_A)
V = trop_mat_mul(C_B, C_B)
W = trop_mat_mul(trop_mat_mul(U, X), V)

# ── Online phase ──
s = Ka[0][0] - M[0,0]   # = a1 + b1
t = Kb[0][0] - M[0,0]   # = a2 + b2
K = W + (s + t)

# ── Decrypt ──
key_material = ",".join(str(int(x)) for x in K.flatten())
aes_key = hashlib.sha256(key_material.encode()).digest()
cipher = AES.new(aes_key, AES.MODE_CBC, iv)
flag = unpad(cipher.decrypt(ct), AES.block_size).decode()
print(flag)
```

---

## Why This Attack Works — Intuition

The protocol's security is supposed to rely on the difficulty of **tropical matrix factorization**: given $K_a = A_1 \odot X \odot B_1$, recover $A_1$ and $B_1$. For general tropical matrices, this is genuinely hard.

But the duo circulant construction collapses the secret space catastrophically:

| What the protocol claims | What actually happens |
|--------------------------|----------------------|
| Secret is an $m \times m$ matrix ($m^2$ unknowns) | Secret is a **single integer** $p_1$ |
| Tropical multiplication "mixes" the secret into $K_a$ | Scalar $p_1$ **passes through** unchanged as a uniform shift |
| Recovering $A_1$ requires solving a tropical system | Recovering $p_1$ requires **reading one entry** of $K_a$ |

The analogy in classical crypto: a "key exchange" where Alice sends $g + a$ and Bob sends $g + b$ over ordinary integers, and the shared key is $g + a + b$. An eavesdropper who knows $g$ trivially recovers $a$ and $b$ by subtraction. That is exactly what is happening here, dressed up in tropical matrix algebra.

> **Formal Classification.** This is an instance of what Chavhan and Chaudhari call **structural collapse**: the algebraic constraints imposed by the duo circulant construction are so rigid that they reduce the effective key space from exponential to trivial, not by any clever algorithmic trick, but by exposing that the protocol's "hard problem" was never actually instantiated.

---

## References

1. B. Amutha and R. Perumal, *"Two party key exchange protocol based on duo circulant matrices for the IoT environment"*, Int. J. Inf. Technol., vol. 16, no. 6, pp. 3585–3596, 2024.
2. S. Chavhan and S. Chaudhari, *"Structural Collapse of the Amutha–Perumal Scheme Based on Duo Circulant Matrices"*, Cryptology ePrint Archive, Paper 2026/354, 2026.
3. E. Stickel, *"A New Method for Exchanging Secret Keys"*, Proc. Third Int. Conf. on Information Technology and Applications (ICITA), vol. 2, pp. 426–430, 2005.
4. V. Shpilrain, *"Cryptanalysis of Stickel's key exchange scheme"*, Proceedings of CSR, LNCS 5010, pp. 283–288, 2008.
5. D. Grigoriev and V. Shpilrain, *"Tropical cryptography"*, Comm. Algebra, vol. 42, no. 6, pp. 2624–2632, 2014.
6. I. Buchinskiy, M. Kotov, and A. Treier, *"Analysis of four protocols based on tropical circulant matrices"*, 2024.

---

## Flag

```
GrizzHacks8{tr0p1c4l_s3m1r1ng5_c0ll4ps3_und3r_4ff1n3_struct}
```
