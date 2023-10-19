Copyright (c) 2023, Circle Internet Financial, LTD. 
All rights reserved

# Go package crypto/zkproofs
This package contains various zero knowledge proofs of knowledge. The source of these 
proofs is CGG21:

Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos Makriyannis, and Udi Peled.
UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts.
CCS '20: Proceedings of the 2020 ACM SIGSAC Conference on Computer and Communications Security.
October 2020. Pages 1769–1787. https://eprint.iacr.org/2021/060. Published in 2020 ACM SIGSAC).

List of proofs in this package
* aff-g Section 6.2 Figure 15
* aff-p Appendix C.3 Figure 26
* dec Appendix C6 Figure 30
* enc section 6.1 Figure 14
* log* Appendix C.2 Figure 25
* mul Appendix C.6 Figure 29
* mul* Appendix C.6. Figure 31

There is also one additional proof aff-g-inv that is based on aff-g.

Some of the proofs require obtaining the randomness used to
generate a Paillier ciphertext. The `crypto/paillier` package
has a function to do this computation.
