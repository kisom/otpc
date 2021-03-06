# otpc: an OTP command line client

**UPDATE**: this has been superceded by the tools in
[cryptutils](https://github.com/kisom/cryptutils).

I hate having my phone on my person, so wrote a command line client
for [HT]OTP-based two-factor auth. This only works with RFC 4226
HOTP / 6238 TOTP two-factor; support is planned for Yubikey HOTP
(and possibly the Yubikey OTP). If you're using Authy, you're on your own.

### Supported OTP:

* Google TOTP (limited to six-character SHA-1 passwords with 30-second
periods)
* RFC 4226 HOTP (SHA-1 6 or 8 character passwords)
* RFC 6238 TOTP (SHA-1 only)

### Planned OTP support:

* RFC 6238 TOTP (256/384/512 6 or 8 character passwords with
  user-definable timesteps)

## Using this:
* extract the secret from the QR code (i.e. with a mobile app)
* call ./otpc -new -type google label (where label is the name to give
  the account) to add a new token
* call ./otpc label (where label is the label you gave in the previous
  step).
* call ./otpc -list to return a list of all accounts stored in the
  account store.
* call ./otpc -remove label to remove the label from the account store.

## Supported types

* google: SHA-1 6-character TOTP with 30-second period
* hotp
* totp

## Import / export

The account store can be imported from PEM or exported to PEM. Pass
either "-export" or "-import", and provide the source (when importing)
or destination (when exporting) file as the only argument. If "-" is used
as a filename, otpc will use either standard input or standard output,
as appropriate.

## The account store:

The accounts are stored internally using a Go map; when dumped to
disk, it is first encoded to JSON, then encrypted using NaCl's
secretbox. The key for NaCl is derived using Scrypt (N=32768, r=8,
p=4) with a 32-byte salt that is randomly generated each time the
file is saved. The salt is stored as the first 32 bytes of the file.

## Sites I've verified this with:

* App.net
* Dropbox
* Github
* Google

## License

otpc is released under the ISC license.
