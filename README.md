# AWS GPG Vault

Stores AWS Access keys in a GPG encrypted file, passing them to the AWS CLI
when a command is invoked.

# Setup

Currently, `aws-gpg-vault` requires some initial legwork in order to get the
credentials prepared.

1. Install (`make install`). Make sure your `go bin` is in your `$PATH`.
2. Run `mkdir -p $HOME/.aws/creds-vault`.
3. Create an encrypted file with the following data:
  ```json
  {
    "Version": 1,
    "AccessKeyId": "MYACCESSKEYID",
    "SecretAccessKey": "MySecretAccesKey",
    "Expiration": ""
  }
  ```
4. Put that file into the creds-vault named for the AWS profile you want to
   associate it with. E.g. `$HOME/.aws/creds-vault/$AWS_PROFILE`.
5. Set your profile config use the vault and that file.
  ```ini
  # $HOME/.aws/config
  [my_profile]
  ...
  credential_process = aws-gpg-vault my_profile
  ...
  ```
6. Remove old section from `$HOME/.aws/credentials`.

# go/x/crypto/openpgp and GPG

The choice to shell out commands to the CLI instead of using the Golang Crypto
library was a conscious choice. Google's openpgp library is several years out of
date and is unable to handle gpg > 2.1. This means no new keyrings, no smartcard
support, and in turn, no Yubikey support.

It could be possible to send commands directly to the GPG agent (using Assuan,
GPG's IPC), but there exists no library yet for Assuan in Golang. So, once one
is written, by myself or others, I'll update the application to utilize it.

# TODO

* [] Support STS Credentials
* [] Add method of adding/updating credentials
* [] Use the gpgagent socket and Assuan instead of shelling out commands
