
# Micali Schnorr

![Micali Schnorr Diagram](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEjEo6C3DqfDzhIxs9oQLsre5hAfZkCdE0yJKnV3jsfng5NgjsdGlX3Hf05fMRjpbf-ZbIe47bVw3wa-FlXrEJmWG_Tka7ZHTyYkNhJacAgHUmHk21Av4S6YKzqUFkqWH66d9fp2FmCxpOCN/s1600/Screen+Shot+2017-10-06+at+3.13.23+PM.png)

[This link](https://www.staff.uni-mainz.de/pommeren/Cryptology/Bitstream/4_Perfect/MicSch.pdf) does a good jon of explaining the Micali Schnorr Generator (MS-DRBG)

For simplicity sake, we are given an integer $n$ and an RSA exponent $e$ will output a sequence of bits. The logic behind this is simple. You start from a secret seed $s$  (the internal state of the DRBG) and you then use $n$ and $e# to do a classic RSA encryption with $s$ as the message:

$$
(s)^{e} \mod n
$$
