const { KEYGEN_PUBLIC_KEY } = process.env

const crypto = require('crypto')
const jwt = require('jsonwebtoken')
const chalk = require('chalk')

async function main() {
  let scheme, key

  // Parse argument flags
  process.argv.forEach((arg, i, argv) => {
    switch (arg) {
      case '--scheme':
      case '-s':
        scheme = argv[i + 1]
        break
      case '--key':
      case '-k':
        key = argv[i + 1]
        break
    }
  })

  // Sanity checks for public key
  if (!KEYGEN_PUBLIC_KEY) {
    throw new Error('Public key is required')
  }

  if (!KEYGEN_PUBLIC_KEY.includes(`-----BEGIN PUBLIC KEY-----`) ||
      !KEYGEN_PUBLIC_KEY.includes(`-----END PUBLIC KEY-----`)) {
    throw new Error('Public key is not valid')
  }

  // Validate flags
  if (!scheme) {
    throw new Error('Scheme is required')
  }

  if (!key) {
    throw new Error('Key is required')
  }

  switch (scheme) {
    // Verify license key that is signed using RSA's PKCS1 v1.5 padding
    case 'RSA_2048_PKCS1_SIGN_V2': {
      // Extract key and signature from the license key string
      const [data, sig] = key.split('.')
      const [prefix, enc] = data.split('/')
      if (prefix !== 'key') {
        throw new Error(`Unsupported prefix '${prefix}'`)
      }

      // Decode the base64 encoded key
      const dec = Buffer.from(enc, 'base64').toString()

      // Verify the signature
      const verifier = crypto.createVerify('sha256')
      verifier.write(`key/${enc}`)
      verifier.end()

      const ok = verifier.verify({ key: KEYGEN_PUBLIC_KEY, padding: crypto.constants.RSA_PKCS1_PADDING }, sig, 'base64')
      if (ok) {
        console.log(chalk.green(`License key is cryptographically valid!`))
        console.log(chalk.gray(`Decoded: ${dec}`))
      } else {
        console.error(chalk.red('License key is not valid!'))
      }

      break
    }
    // Verify license key that is signed using RSA's PKCS1-PSS padding
    case 'RSA_2048_PKCS1_PSS_SIGN_V2': {
      // Extract key and signature from the license key string
      const [data, sig] = key.split('.')
      const [prefix, enc] = data.split('/')
      if (prefix !== 'key') {
        throw new Error(`Unsupported prefix '${prefix}'`)
      }

      // Decode the base64 encoded key
      const dec = Buffer.from(enc, 'base64').toString()

      // Verify the signature
      const verifier = crypto.createVerify('sha256')
      verifier.write(`key/${enc}`)
      verifier.end()

      const ok = verifier.verify({ key: KEYGEN_PUBLIC_KEY, padding: crypto.constants.RSA_PKCS1_PSS_PADDING }, sig, 'base64')
      if (ok) {
        console.log(chalk.green(`License key is cryptographically valid!`))
        console.log(chalk.gray(`Decoded: ${dec}`))
      } else {
        console.error(chalk.red('License key is not valid!'))
      }

      break
    }
    // Decrypt license key that is encrypted using RSA's PKCS1 v1.5 padding
    case 'RSA_2048_PKCS1_ENCRYPT': {
      // Decode the base64 encoded key
      const buf = Buffer.from(key, 'base64')

      // Decrypt the key
      try {
        const decryptedKey = crypto.publicDecrypt({ key: KEYGEN_PUBLIC_KEY, padding: crypto.constants.RSA_PKCS1_PADDING }, buf)

        console.log(chalk.green(`License key is cryptographically valid!`))
        console.log(chalk.gray(`Decrypted: ${decryptedKey}`))
      } catch (e) {
        console.error(chalk.red('License key is not valid!'))
      }

      break
    }
    // Verify a JWT license key that is signed using the RS256 algo
    case 'RSA_2048_JWT_RS256': {
      try {
        const dec = jwt.verify(key, KEYGEN_PUBLIC_KEY, { algorithms: ['RS256'] })

        console.log(chalk.green(`License key is cryptographically valid!`))
        console.log(
          chalk.gray(`Claims: ${JSON.stringify(dec, null, 2)}`)
        )
      } catch (e) {
        console.error(
          chalk.red(`License key is not valid (${e.message})`)
        )
      }

      break
    }
    default:
      throw new Error(`Unsupported scheme '${scheme}'`)
  }
}

main().catch(err =>
  console.error(
    chalk.red(`Error: ${err.message}`)
  )
)