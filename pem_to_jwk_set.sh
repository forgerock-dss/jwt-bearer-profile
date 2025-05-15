#!/bin/bash

# === CONFIG ===
PUBKEY_FILE="public_key.pem"
KID="1234567890"

# === Extract Modulus and Exponent using OpenSSL ===
# Outputs in base64 (we'll convert to base64url below)
RSA_DUMP=$(openssl rsa -pubin -in "$PUBKEY_FILE" -text -noout)

MOD_HEX=$(echo "$RSA_DUMP" | awk '/Modulus:/,/Exponent:/' | grep -v "Modulus:" | grep -v "Exponent:" | tr -d ' \n:')
EXP_DEC=$(echo "$RSA_DUMP" | awk '/Exponent:/ {print $2}')

# === Convert hex modulus to raw binary and base64url ===
N_B64=$(echo "$MOD_HEX" | xxd -r -p | openssl base64 -A | tr '+/' '-_' | tr -d '=')
E_B64=$(printf "%x" "$EXP_DEC" | xxd -r -p | openssl base64 -A | tr '+/' '-_' | tr -d '=')

# === Output JWK Set ===
jq -n --arg kty "RSA" \
      --arg alg "RS256" \
      --arg use "sig" \
      --arg kid "$KID" \
      --arg n "$N_B64" \
      --arg e "$E_B64" \
      '{
        keys: [
          {
            kty: $kty,
            alg: $alg,
            use: $use,
            kid: $kid,
            n: $n,
            e: $e
          }
        ]
      }'
