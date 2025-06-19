ppdeep
======

This is a pure-Python library for computing context triggered piecewise hashes
(CTPH), also called fuzzy hashes, or often ssdeep after the name of a popular
tool. At a very high level, fuzzy hashing is a way to determine whether two
inputs are similar, rather than identical. Fuzzy hashes are widely adopted in
digital forensics and malware detection.

This implementation is based on SpamSum by Dr. Andrew Tridgell.

Usage
-----

To compute a fuzzy hash, simply use `hash()` function:

```
>>> import ppdeep
>>> h1 = ppdeep.hash('The equivalence of mass and energy translates into the well-known E = mc²')
>>> h1
'3:RC0qYX4LBFA0dxEq4z2LRK+oCKI9VnXn:RvqpLB60dx8ilK+owX'
>>> h2 = ppdeep.hash('The equivalence of mass and energy translates into the well-known E = MC2')
>>> h2
'3:RC0qYX4LBFA0dxEq4z2LRK+oCKI99:RvqpLB60dx8ilK+oA'
```

To calculate level of similarity, use `compare()` function which returns an
integer value from 0 to 100 (full match):

```
>>> ppdeep.compare(h1, h2)
34
```

Function `hash_from_file()` accepts a filename as argument and calculates the
hash of the contents of the file:

```
>>> ppdeep.hash_from_file('.bash_history')
'1536:EXM36dG36x3KW732vOAcg3EP1qKlKozcK0z5G+lEPTssl/7eO7HOBF:tKlKozcWT0'
```

Installation
------------

```
$ pip install ppdeep
```

If you want to use the latest version of the code, you can install it from Git:

```
$ git clone https://github.com/elceef/ppdeep.git
$ cd ppdeep
$ pip install .
```
