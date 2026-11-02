// Fixture: Node crypto, Web Crypto, node-forge, plus near-misses.
const crypto = require('crypto');
const forge = require('node-forge');

const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
crypto.generateKeyPair("ec", { namedCurve: "P-256" }, cb);
crypto.generateKeyPairSync(`ed25519`);
const md5 = crypto.createHash('md5').update(s).digest('hex');
const c1 = crypto.createCipheriv('aes-128-ecb', key, null);   // generic AES rule
const c2 = crypto.createCipheriv('des-ede3-cbc', key, iv);     // generic 3DES rule
const c3 = crypto.createCipheriv('des-cbc', key, iv);          // single DES
const c4 = crypto.createCipheriv('rc4', key, '');
await crypto.subtle.generateKey({ name: "RSA-OAEP", modulusLength: 4096 }, true, ops);
await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ops);
const kp = forge.pki.rsa.generateKeyPair({ bits: 1024, e: 0x10001 });

// Near-misses:
const h = crypto.createHash('sha256');
const description = "describes the rsa module";
const gcm = crypto.createCipheriv(algo, key, iv);
