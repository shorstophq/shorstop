<?php
// Fixture: PHP crypto, plus near-misses.
use phpseclib3\Crypt\RSA;

$res = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
$ec = openssl_pkey_new(["private_key_type" => OPENSSL_KEYTYPE_EC]);
$h = md5($password);
$s = sha1_file($path);
$x = hash('sha1', $data);
$enc = openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv); // generic AES rule
mcrypt_encrypt(MCRYPT_DES, $key, $data, MCRYPT_MODE_ECB);

// Near-misses:
$ok = hash('sha256', $data);
$md5_column = 'checksum';
