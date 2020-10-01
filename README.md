# Example Cryptographic Verification
This is an example of cryptographically validating license keys, and
extracting embedded tamper-proof data within the key for offline use, all
with your Keygen account's public key. You can find your public key within
[your account's settings page](https://app.keygen.sh/settings).

Cryptographically validating encrypted and signed licenses can be used
to implement offline licensing, as well as adding additional security to
your licensing model. All that is needed to cryptographically validate
a license is your account's RSA public key.

The license's policy _must_ implement one of the following [schemes](https://keygen.sh/docs/api/#policies-create-attrs-scheme):

- `RSA_2048_PKCS1_ENCRYPT`
- `RSA_2048_PKCS1_SIGN`
- `RSA_2048_PKCS1_PSS_SIGN`
- `RSA_2048_JWT_RS256`

## Running the example

First up, add an environment variable containing your public key:
```bash
# Your Keygen account's public key (make sure it is *exact* - newlines and all)
export KEYGEN_PUBLIC_KEY=$(printf %b \
  '-----BEGIN PUBLIC KEY-----\n' \
  'zdL8BgMFM7p7+FGEGuH1I0KBaMcB/RZZSUu4yTBMu0pJw2EWzr3CrOOiXQI3+6bA\n' \
  # …
  'efK41Ml6OwZB3tchqGmpuAsCEwEAaQ==\n' \
  '-----END PUBLIC KEY-----')
```

You can either run each line above within your terminal session before
starting the app, or you can add the above contents to your `~/.bashrc`
file and then run `source ~/.bashrc` after saving the file.

Next, install dependencies with [`yarn`](https://yarnpkg.comg):
```
yarn
```

Then run the script, passing in the `key` as well as the `scheme`:
```
yarn start --scheme RSA_2048_PKCS1_PSS_SIGN --key SOME_LICENSE_KEY_HERE
yarn start -s RSA_2048_PKCS1_PSS_SIGN -k SOME_LICENSE_KEY_HERE
```

How a given license key is validated will depend on the scheme. Please
review the code for a more thorough overview of how each scheme is
validated. Be sure to copy your public key correctly - your keys will
fail validation if it is copied incorrectly. You can find your public
key in [your account's settings](https://app.keygen.sh/settings).

## Questions?

Reach out at [support@keygen.sh](mailto:support@keygen.sh) if you have any
questions or concerns!
