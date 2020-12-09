<p align="center">
    <img src="pics/logo.png">
</p>

# intro

`ciphart` can do:

- **encrypt/decrypt:** only encrypt/decrypt a file using xchacha20 (i.e. `-e` and `-d` actions).
- **derive better keys:** only derive a more secure key using a novel key derivation function (i.e.
  `-k` action).
- **both:** do both (i.e. `-ek` and `-dk` actions).

but, you may ask, why yet another tool?  isn't the tool
[`scrypt`](https://www.tarsnap.com/scrypt.html) enough?  answer is _no_,
here is why:

- **guaranteed entropy:** the novel key derivation function is the only one
  out there that objectively quantifies the amount of increased security
  against brute-forcing attacks in the unit of entropy bits.  this is also
  guaranteed independent of attacker's hardware.
- **modern crypto algorithm:** xchacha20 is a new algorithm, and not much
  tools out there.  hence the need to create a new tool.
- **made for humans:** neat command-line interface that allows to accept
  both, the password and the input file via STDIN; something not possible
  with some tools such as [`scrypt`](https://www.tarsnap.com/scrypt.html).
- **made with _love_:** _looks_ very beautiful.  most likely it is _the_
  most beautiful crypo cli app out there.

<p align="center">
    <img src="pics/1.png">
</p>

<p align="center">
    <img src="pics/2.png">
</p>

# installation

1.  install [`libsodium`](https://libsodium.gitbook.io/doc/).
2. run `make`.
3. somehow put `ciphart` executable somewhere in `PATH` (personally i
   symbolically linked it to `/usr/bin/ciphart`).

# how entropy is calculated?  why is it guaranteed?

[the _idea_ is explained
here](https://crypto.stackexchange.com/questions/85676/how-to-estimate-the-maximum-computational-cost-bound-for-key-derivation-function).
for more info, you may read the code (it's small), or ask me by submitting
an issue.

note that this entropy calculation is not a mere heuristic.  this is
guaranteed to be true regarless of attacker's hardware/software
implementation of xchacha20.  i.e. regardless of how fast attacker's
xchacha20 implementation is, the effect of the KDF is maintained.  e.g. if
the KDF claims to inject `20` bits of entropy, it is held as follows:  the
attacker's password bruteforcing will increase exactly as if your password
had `20` extra entropy bits.


# how to utter `ciphart`?

two options:

- `sai fart` (preferred).
- `sip heart`.
