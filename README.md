# secret box
This is a wrapper using the [crypto/nacl/secretbox](https://godoc.org/golang.org/x/crypto/nacl/secretbox) library as a easy to use symmetric encryption to string format with everything you need to decrypt.

The secrets are encrypted using ([NaCl](http://nacl.cr.yp.to/) [Secret Box](http://nacl.cr.yp.to/secretbox.html):
[Salsa20](http://en.wikipedia.org/wiki/Salsa20) +
[Poly1305-AES](http://en.wikipedia.org/wiki/Poly1305-AES)).

The encrypted values are returned as a box with all the values needed to decrypt it included with the correct key. It's important the the consumer of this library implement a method to store the key securely and keep track of which key goes to which ciphertext.  

The structure of `/crypto` is inspired by the [Shopify/ejson crypto wrapper](https://github.com/Shopify/ejson/tree/master/crypto).