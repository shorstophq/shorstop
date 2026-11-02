#!/bin/sh
# Regenerates every fixture in this directory. Throwaway test keys only.
# Then: go test ./internal/detect/cert -update, and review the diff.
set -eu
cd "$(dirname "$0")"
go run gen.go

rm -f id_ed25519_enc id_ed25519_enc.pub id_rsa id_rsa.pub
ssh-keygen -q -t ed25519 -N 'fixture' -C 'enc@fixture' -f id_ed25519_enc   # encrypted OpenSSH
ssh-keygen -q -t rsa -b 3072 -N '' -C 'rsa@fixture' -f id_rsa              # unencrypted OpenSSH
rm id_ed25519_enc.pub
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null |
  openssl pkcs8 -topk8 -v2 aes-256-cbc -passout pass:fixture -out encrypted-pkcs8.key
openssl dhparam -out dhparam.pem 1024 2>/dev/null

{
  echo '# authorized_keys fixture: a comment, RSA, ECDSA, a garbage line, a FIDO key'
  echo "$(cat id_rsa.pub)"
  ssh-keygen -q -t ecdsa -b 384 -N '' -C ecdsa@fixture -f tmp_ecdsa && cat tmp_ecdsa.pub && rm tmp_ecdsa tmp_ecdsa.pub
  echo 'ssh-rsa not-a-valid-key garbage'
} > authorized_keys

head -c 512 /dev/urandom > store.p12
printf 'not\000a der file' > junk.der

# SHA-1-signed certificate (Go refuses to create SHA-1 signatures).
openssl req -x509 -sha1 -newkey rsa:1024 -nodes -keyout /dev/null -subj /CN=legacy-sha1 \
  -not_before 20260101000000Z -not_after 20360101000000Z -out legacy-sha1.pem 2>/dev/null

# A FIDO security-key public key (sk-ssh-ed25519): no hardware needed to
# encode one, only the wire format: string type, string key, string application.
python3 - >> authorized_keys <<'PY'
import base64, os, struct
s = lambda b: struct.pack(">I", len(b)) + b
t = b"sk-ssh-ed25519@openssh.com"
print(t.decode(), base64.b64encode(s(t) + s(os.urandom(32)) + s(b"ssh:")).decode(), "security-key@fixture")
PY

# Private keys embedded in Go source: a raw string (decodes) and an
# escaped one-line string (marker only).
{
  echo '// Fixture: keys embedded in source code.'
  echo 'package fixture'
  echo
  printf 'const raw = `'; cat rsa-pkcs1.key; echo '`'
  echo
  printf 'const escaped = "%s"\n' "$(awk '{printf "%s\\\\n", $0}' ec-pkcs8.key)"
} > embedded.go.txt

cat > README.md <<'MD'
# Fixture: documentation placeholders are not findings

Paste your certificate here:

    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----

And a lower-case "-----BEGIN something-----" is not a PEM marker.
MD
