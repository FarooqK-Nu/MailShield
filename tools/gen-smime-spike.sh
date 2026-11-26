#!/usr/bin/env bash
# Regenerates fixtures/smime with OpenSSL. Test-only certificates; private keys are not kept.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p fixtures/smime
out="fixtures/smime"
tmp="fixtures/.smime-tmp"
rm -rf "$tmp"
mkdir "$tmp"
trap 'rm -rf "$tmp"' EXIT
export MSYS_NO_PATHCONV=1

ca() {
  openssl req -x509 -newkey rsa:2048 -noenc -keyout "$tmp/$1.key" -out "$tmp/$1.crt" -days 36500 \
    -subj "/CN=$2" -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
}
ca ca "MailShield TEST CA"
ca other "Unrelated TEST CA"

openssl req -newkey rsa:2048 -noenc -keyout "$tmp/alice.key" -out "$tmp/alice.csr" \
  -subj "/CN=Alice (test)" 2>/dev/null
printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=emailProtection\nsubjectAltName=email:alice@acme.example\n' > "$tmp/ext.cnf"
openssl x509 -req -in "$tmp/alice.csr" -CA "$tmp/ca.crt" -CAkey "$tmp/ca.key" -CAcreateserial \
  -days 36500 -extfile "$tmp/ext.cnf" -out "$tmp/alice.crt" 2>/dev/null

printf 'Please review the attached agenda.\n' > "$tmp/body.txt"
openssl cms -sign -in "$tmp/body.txt" -text -signer "$tmp/alice.crt" -inkey "$tmp/alice.key" \
  -md sha256 -from alice@acme.example -to bob@acme.example -subject "Signed test" -out "$tmp/raw.eml"

# Normalise to CRLF: OpenSSL line endings differ between Windows and Linux.
node -e "const fs=require('fs');const[i,o]=process.argv.slice(1);fs.writeFileSync(o,fs.readFileSync(i,'latin1').replace(/\r*\n/g,'\r\n'),'latin1')" \
  "$tmp/raw.eml" "$out/signed.eml"
cp "$tmp/ca.crt" "$tmp/other.crt" "$tmp/alice.crt" "$out/"
echo "Wrote $out"
