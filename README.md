GPGME
-----

A golang bridge to GPGME

Dependencies
------------

This project uses cgo. It will look to link against the following libraries:

* [libgpg-error][gpg-error]
* [libassuan][assuan]
* [libgpgme][gpgme] 

On OSX (or macOS) you can install dependencies via `brew install libgpg-error libassuan gpgme`

[gpg-error]: https://www.gnupg.org/related_software/libgpg-error/index.html "GnuPG libgpg-error"
[assuan]: https://www.gnupg.org/related_software/libassuan/index.html "GnuPG libassuan"
[gpgme]: https://www.gnupg.org/related_software/gpgme/index.html "GnuPG gpgme"
