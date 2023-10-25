Copyright (c) 2023, Circle Internet Financial, LTD. All rights reserved.

  SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

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
