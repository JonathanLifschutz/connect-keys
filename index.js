/* global process */

/**
 * Module dependencies
 */

var fs = require('fs')
var crypto = require('crypto')
var mkdirp = require('mkdirp')
var path = require('path')
var pemjwk = require('pem-jwk')
var childProcess = require('child_process')

/**
 * Constructor
 */

function AnvilConnectKeys (directory) {
  // base directory for keys to be read from and written to
  this.directory = path.join(directory || process.cwd(), 'keys')

  // signature key pair file paths
  this.sig = {
    pub: path.join(this.directory, 'sig.rsa.pub.pem'),
    prv: path.join(this.directory, 'sig.rsa.prv.pem')
  }

  // encryption key pair file paths
  this.enc = {
    pub: path.join(this.directory, 'enc.rsa.pub.pem'),
    prv: path.join(this.directory, 'enc.rsa.prv.pem')
  }

  // setup token
  this.setup = path.join(this.directory, 'setup.token')
}

/**
 * Generate key pairs
 */

function generateKeyPairs () {
  var done = false
  while (!done) {
    // sig and enc keypair generation is an atomic action
    AnvilConnectKeys.generateKeyPair(this.sig.pub, this.sig.prv)
    AnvilConnectKeys.generateKeyPair(this.enc.pub, this.enc.prv)
    done = true
  }
}

AnvilConnectKeys.prototype.generateKeyPairs = generateKeyPairs

/**
 * Generate single key pair
 */

function generateKeyPair (pub, prv) {
  try {
    mkdirp.sync(path.dirname(pub))
    mkdirp.sync(path.dirname(prv))

    childProcess.execFileSync('openssl', [
      'genrsa',
      '-out',
      prv,
      '4096'
    ], {
      stdio: 'ignore'
    })

    childProcess.execFileSync('openssl', [
      'rsa',
      '-pubout',
      '-in',
      prv,
      '-out',
      pub
    ], {
      stdio: 'ignore'
    })
  } catch (e) {
    throw new Error(
      'Failed to generate keys using OpenSSL. Please ensure you have OpenSSL ' +
      'installed and configured on your system.'
    )
  }
}

AnvilConnectKeys.generateKeyPair = generateKeyPair

/**
 * Load key pairs
 */

function loadKeyPairs () {
  var sig = AnvilConnectKeys.loadKeyPair(this.sig.pub, this.sig.prv, 'sig')
  var enc = AnvilConnectKeys.loadKeyPair(this.enc.pub, this.enc.prv, 'enc')

  var jwkKeys = []
  jwkKeys.push(sig.jwk.pub, enc.jwk.pub)

  return {
    sig: sig.pem,
    enc: enc.pem,
    jwks: {
      keys: jwkKeys
    }
  }
}

AnvilConnectKeys.prototype.loadKeyPairs = loadKeyPairs

/**
 * Load single key pair
 */

function loadKeyPair (pub, prv, use) {
  var pubPEM, prvPEM, pubJWK

  try {
    pubPEM = fs.readFileSync(pub).toString('ascii')
  } catch (e) {
    throw new Error('Unable to read the public key from ' + pub)
  }

  try {
    prvPEM = fs.readFileSync(prv).toString('ascii')
  } catch (e) {
    throw new Error('Unable to read the private key from ' + pub)
  }

  try {
    pubJWK = pemjwk.pem2jwk(pubPEM)
  } catch (e) {
    throw new Error('Unable to convert the public key ' + pub + ' to a JWK')
  }

  return {
    pem: {
      pub: pubPEM,
      prv: prvPEM
    },
    jwk: {
      pub: {
        kty: pubJWK.kty,
        use: use,
        alg: 'RS256',
        n: pubJWK.n,
        e: pubJWK.e
      }
    }
  }
}

AnvilConnectKeys.loadKeyPair = loadKeyPair

/**
 * Generate setup token
 */

function generateSetupToken (tokenPath) {
  mkdirp.sync(path.dirname(tokenPath))

  var token = crypto.randomBytes(256).toString('hex')
  try {
    fs.writeFileSync(tokenPath, token, 'utf8')
  } catch (e) {
    throw new Error('Unable to save setup token to ' + tokenPath)
  }
  return token
}

AnvilConnectKeys.generateSetupToken = generateSetupToken

/**
 * Load setup token
 */

function loadSetupToken (tokenPath) {
  return fs.readFileSync(tokenPath, 'utf8').toString().trim()
}

AnvilConnectKeys.loadSetupToken = loadSetupToken

/**
 * Generate setup token from scoped path
 */

function generateSetupTokenLocal () {
  return AnvilConnectKeys.generateSetupToken(this.setup)
}

AnvilConnectKeys.prototype.generateSetupToken = generateSetupTokenLocal

/**
 * Load setup token from scoped path
 */

function loadSetupTokenLocal () {
  return AnvilConnectKeys.loadSetupToken(this.setup)
}

AnvilConnectKeys.prototype.loadSetupToken = loadSetupTokenLocal

/**
 * Export
 */

module.exports = AnvilConnectKeys
