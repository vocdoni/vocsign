#!/bin/bash
set -e

# Directories
OUT_DIR="vocsign/test/certs"
mkdir -p $OUT_DIR

# 1. Create Root CA (Fake idCAT/FNMT)
openssl req -x509 -new -nodes -keyout $OUT_DIR/ca.key -sha256 -days 3650 -out $OUT_DIR/ca.crt -subj "/C=ES/O=Fake Government CA/CN=Fake Root CA"

# 2. Create User Key
openssl genrsa -out $OUT_DIR/user.key 2048

# 3. Create User CSR
openssl req -new -key $OUT_DIR/user.key -out $OUT_DIR/user.csr -subj "/C=ES/O=Citizen/CN=JUAN PEREZ GARCIA 12345678Z"

# 4. Create Extension File for User Cert (mimic idCAT/FNMT attributes roughly)
cat > $OUT_DIR/user.ext <<EOF
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, nonRepudiation, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection
subjectAltName = email:juan.perez@example.com
EOF

# 5. Sign User Cert with CA
openssl x509 -req -in $OUT_DIR/user.csr -CA $OUT_DIR/ca.crt -CAkey $OUT_DIR/ca.key -CAcreateserial -out $OUT_DIR/user.crt -days 365 -sha256 -extfile $OUT_DIR/user.ext

# 6. Export to PKCS#12
openssl pkcs12 -export -out $OUT_DIR/user.p12 -inkey $OUT_DIR/user.key -in $OUT_DIR/user.crt -certfile $OUT_DIR/ca.crt -passout pass:password -name "Juan Perez (Fake ID)" -legacy

echo "Certificates generated in $OUT_DIR"
