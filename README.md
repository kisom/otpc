# otpc: an OTP command line client

I hate having my phone on my person, so wrote a command line client
for [HT]OTP-based two-factor auth. This only works with RFC 4226
HOTP / 6238 TOTP two-factor; support is planned for Yubikey HOTP
(and possibly the Yubikey OTP). If you're using Authy, you done
fucked up and are shit out of luck.

### Supported OTP:

* Google TOTP (limited to six-character SHA-1 passwords with 30-second
periods)

### Planned OTP support:

* RFC 4226 HOTP (SHA-1 6 or 8 character passwords)
* RFC 6238 TOTP (SHA-1/256/384/512 6 or 8 character passwords with
user-definable timesteps)

## Using this:
* extract the secret from the QR code (i.e. with a mobile app)
* call ./otpc -new -type google label (where label is the name to give the account)

## The account store:

The accounts are stored internally using a Go map; when dumped to
disk, it is first encoded to JSON, then encrypted using NaCl's
secretbox. The key for NaCl is derived using Scrypt (N=32768, r=8,
p=4) with a 32-byte salt that is randomly generated each time the
file is saved. The salt is stored as the first 32 bytes of the file.

## License

otpc is released under the ISC license.