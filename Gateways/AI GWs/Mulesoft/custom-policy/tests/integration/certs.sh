#!/bin/bash
# A throwaway CA and a server certificate for the mock AIRS host "airs", for the Local Mode harness only.
set -euo pipefail
out=${1:?output directory}
mkdir -p "$out" && cd "$out"
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=itest-ca" -keyout ca.key -out ca.crt 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=airs" -keyout airs.key -out airs.csr 2>/dev/null
printf 'subjectAltName=DNS:airs\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' > ext.cnf
openssl x509 -req -in airs.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 30 -extfile ext.cnf -out airs.crt 2>/dev/null
cat /etc/ssl/certs/ca-certificates.crt ca.crt > ca-bundle.crt
chmod 644 ./*.crt ./*.key
rm -f airs.csr ext.cnf ca.srl
echo "certificates in $out"
