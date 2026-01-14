# Circulant Cipher (NTT)

**Category:** Crypto
**Difficulty:** Medium
**Tags:** linear algebra, NTT, convolution

---

## 1. What the Cipher *Claims* to Do

We work over the prime field:

$$
p = 998244353 = 119 \cdot 2^{23} + 1
$$

This prime is popular because it supports large power-of-two roots of unity, making NTT fast.

Plaintext is interpreted as a length-$N$ vector (bytes padded with zeros):

- $N = 256$
- plaintext vector $\mathbf{p} \in \mathbb{F}_p^N$

Encryption is **multi-round circular convolution**:

$$
\mathbf{s}_0 = \mathbf{p}
$$

$$
\mathbf{s}_{r+1} = \mathbf{s}_r \circledast \mathbf{k}_r \pmod p \quad \text{for } r = 0,1,\dots,R-1
$$

$$
\mathbf{c} = \mathbf{s}_R
$$

Where each round key $\mathbf{k}_r$ is derived from a hidden seed using an XOF, in this case SHAKE-256.

$$
\mathbf{k}_r = \text{Expand}(\text{seed}, r)
$$

So ciphertext is:

$$
\mathbf{c} = \mathbf{p} \circledast \mathbf{k}_0 \circledast \mathbf{k}_1 \circledast \cdots \circledast \mathbf{k}_{R-1} \pmod p
$$

Where:

- $\mathbf{p}$ is the plaintext vector
- $\mathbf{k}$ is the secret key
- $\mathbf{c}$ is the ciphertext
- $p = 998244353$

---

## 2. Time-Domain View (What You See)

In the time domain, encryption looks like a messy mixing operation:

```
plaintext:  p0  p1  p2  p3  ... p255
key:        k0  k1  k2  k3  ... k255
-----------------------------------
ciphertext: c0  c1  c2  c3  ... c255
```

Each output element depends on **every key element**, rotated cyclically.

This *feels* secure.
It is not.

---

## 3. Hidden Structure: Circulant Matrix

Circular convolution is equivalent to multiplying by a **circulant matrix**:

For a key vector $\mathbf{k}$, define $K$ as:

$$
K =
\begin{pmatrix}
k_0 & k_1 & k_2 & \cdots & k_{N-1} \\
k_{N-1} & k_0 & k_1 & \cdots & k_{N-2} \\
\vdots & \vdots & \vdots & \ddots & \vdots \\
k_1 & k_2 & k_3 & \cdots & k_0
\end{pmatrix}
$$

Then:

$$
\mathbf{c} = K \mathbf{p}
$$

multi-round just multiplies by more circulant matrices:

$$
\mathbf{c} = K_{R-1} \cdots K_1 K_0 \mathbf{p}
$$

And the product of the circulant matrice is **still circulant**. So all rounds collapse into a single transform. This is extremely important, and the root cause for this extremely fatal flaw.

---

## 4. NTT: The Transform That Ruins Everything

Circulant matrices are diagonalized by the Fourier transform.

Over $\mathbb{F}_p$ we use the **Number Theoretic Transform (NTT)**

Key property (convolution theorem):

$$
\text{NTT}(\mathbf{a} \circledast \mathbf{b}) = 
\text{NTT}(\mathbf{a}) \odot \text{NTT}(\mathbf{b})
$$

Whereas $\odot$ means element-wise multiplcation

### What the NTT does conceptually:

![Image](https://www.researchgate.net/publication/235995761/figure/fig8/AS%3A668685589037087%401536438476565/Signal-flow-graph-for-8-point-FFT.png)

![Image](https://media.springernature.com/lw685/springer-static/image/chp%3A10.1007%2F978-3-319-76029-2_4/MediaObjects/450626_1_En_4_Fig1_HTML.png)

![Image](https://www-structmed.cimr.cam.ac.uk/Course/Convolution/convolution.gif)

![Image](https://www.eeeguide.com/wp-content/uploads/2019/10/Convolution-Theorem-9.jpg)

---

## 5. What Multi-Rounds Become in Frequency Domain

Define:

$$
\hat{p} = \text{NTT}(p), \; \hat{c} = \text{NTT}(c), \; \hat{k}_r = \text{NTT}(k_r)
$$

One round:

$$
\hat{s}_{r+1} = \hat{s}_r \circledast \hat{k}_r
$$

After $R$ rounds:

$$
\hat{c} = \hat{p} \circledast \hat{k}_0 \circledast \hat{k}_1 \circledast \vdots \circledast \hat{k}_{R-1}
$$

Define an **effective key in frequency domain**:

$$
\hat{k}_{\text{eff}} = \prod^{R-1}_{r=0} \hat{k}_r
$$

---

## 6. Known Plaintext = Immediate Key Recovery

Because the plaintext is known:

$p = \text{"Honey, where's my supaaasuit?!"}$

And its ciphertext $c_1$

Transform both:

$$
\hat{p} = \text{NTT}(p),\;\hat{c}_1 = \text{NTT}(c_1)
$$

Then, recover the effective key per bin:

$$
\hat{k}_{\text{eff,i}} = \hat{c}_1 \cdot \hat{p}_{i}^{-1}
$$

### Visually:

```
p̂[i] × k̂[i] = ĉ[i]
        │
        ▼
      k̂[i] = ĉ[i] / p̂[i]
```

Repeat for all $i$, then apply inverse NTT:

$$
\mathbf{k} = \text{NTT}^{-1}(\widehat{\mathbf{k}})
$$

The **entire secret key** is recovered.

---

## 7. Decrypting the Flag (Same Trick, Other Direction)

The flag ciphertext satisfies:

$$
\widehat{c}^{(\text{flag})}_i = \widehat{p}^{(\text{flag})}_i \cdot \widehat{k}_i
$$

Invert again:

$$
\widehat{p}^{(\text{flag})}_i =
\widehat{c}^{(\text{flag})}_i \cdot \widehat{k}_i^{-1}
$$

Apply inverse NTT and strip padding.

Flag obtained.

---

## 8. Why This Always Breaks (Example diagrams)

**Fatal properties:**

- Linear operation (convolution)
- Reused key (same seed, same effective key)
- Known transform (NTT)
- Circulant structure (diagnolized by NTT)
- No mixing between frequency bins after transform.

Once transformed, there is **no interaction between frequencies**.

That is the worst possible thing you can do in cryptography.

---

## 9. Exploit Summary (CTF Checklist)

- [x] Compute $\hat{p}$ from known plaintext
- [x] compute $\hat{c}_1$
- [x] Recover $\hat{k}_{\text{eff}}$ by division per bin
- [x] Compute $\hat{p}^{\text{flag}}$ by dividing $\hat{c}^{\text{(flag)}}$
- [x] iNTT -> 
bytes -> flag

**Solve steps:**

1. Apply NTT to known plaintext and ciphertext
2. Divide frequency components
3. Inverse NTT → recover key
4. Divide flag ciphertext by key
5. Inverse NTT → flag

---

## Final Takeaway

> **If your cipher becomes diagonal under a known transform, it is already broken.**

This challenge demonstrates why:

- Complexity != security
- Structure is information
- Algebra beats secrecy

---

### Flag

```bash
cd Circular/solution/
python solver.py                    
GRIZZ{c1rcul4nt_m4t_l1n34r_r3c0v3ry}
```

Thanks for reading, please reach out to me on discord if you have any questions!


<img width="546" height="894" alt="image" src="https://github.com/user-attachments/assets/765af27b-b8d1-4120-9fba-9f81512431a8" />


---

