# Cipher-Solver
This project is a cipher solver written in C used to solve challenges from MisteryTwister, a crypto challenge contest. Basic cipher algorithms like Caesar, ROT13, Vigenere, ... will also be implemented.

I am currently working on the following challenge : **The Lady Liz Challenge**, submitted by Elijah Cross on 2025-02-10. The goal of this project is to decrypt the message from 'ciphertext.txt', but neither the keys pair nore the Intermediate Vector (IV) are given... Knowing that the two keys are each a permutation of the printable ASCII caracters, this would lead to **95²x(95!)² combinaisons**... Bruteforce attack is impossible, there must be a vulnerability somewhere in the cipher. No solution has been proposed yet (2025-02-28).

Use **./solver -help** to get information on how to use the code.

You can find the challenge [here](https://mysterytwister.org/challenges).
