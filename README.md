# MD2-Cryptographic-Hash-Function-Python

I have created the MD2 cryptographic hash function in Python.
I researched the MD2 specification and there was an update to the original specification, with an additional XOR to be used for creating the checksum:
C[j] = C[j] ^ (S[c^L])
<br />

The original specification can be found here: https://www.rfc-editor.org/rfc/pdfrfc/rfc1319.txt.pdf <br />
The specification code update can be found here: https://www.rfc-editor.org/rfc/inline-errata/rfc1319.html
