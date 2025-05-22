#!/bin/bash

# Config parameters to modify
SUB="cde373a9-51ee-41e2-bdfe-624cfdc02514"    # This should be the _id value of the user
TENANT="openam-darinder-wforce.forgeblocks.com" # For example openam-my-tenant.forgerock.io
REALM="alpha"
CLIENT_ID="jwt_bearer_client"
JWTAGENT="sampleIssuer"

# No need to modify these config parameters
PRIVATE_KEY="private_key.pem"
PUBLIC_KEY="public_key.pem"
IDM_ENDPOINT="https://${TENANT}/openidm/managed/${REALM}_user?_fields=userName,givenName,sn,mail,accountStatus&_prettyPrint=true&_queryFilter=true&_pageSize=1"
TOKEN_URL="https://${TENANT}:443/am/oauth2/realms/root/realms/${REALM}/access_token"
SCOPE="test"

# Function: Setup Guidance
setup() {
  cat <<EOF

User Setup
------------------------------------------
1. Create a new user via the Platform UI: Identities > Manage
2. Click into the user and note the _id value of the user from the URL and update the SUB variable in this script

OAuth2 Client Setup
------------------------------------------
1. From the Platform UI > Applications > Custom Application > OIDC - OpenID Connect page. Create a Native/SPA Public OAuth2 client called $CLIENT_ID
2. On the Sign On tab, set Grant Types to JWT Bearer only and Scopes to be $SCOPE only and hit Save.
4. Expand Show advanced settings > Access and Set Response Types to token only and hit Save.
5. Click Authentication below Access and set Token Endpoint Auth Method to client_secret_post and hit Save.

Trusted JWT Issuer Setup
------------------------------------------
1. In Access Management Native Console UI. Goto > Applications > OAuth 2.0 > Trusted JWT Issuer > Add Trusted JWT Issuer Agent
2. Set the Agent ID to: $JWTAGENT
3. Set JWT Issuer to the OAuth2 Client ID created earlier: $CLIENT_ID
4. Copy the Output for the Generating JWK Set (including the {}) and paste into the JWK Set parameter.
5. Set Allowed Subjects to: $SUB and hit Save Changes.
EOF
  echo
  read -n1 -r -p "Press 'q' to quit and complete setup manually, or any other key to continue: " key
  echo
  if [[ "$key" =~ [qQ] ]]; then
    echo "Exiting setup..."
    exit 0
  fi
}

openSSLCheck() {
  echo "------------------------------------------"
  echo
  hash openssl &>/dev/null
  if [ $? -eq 1 ]; then
    echo >&2 "OpenSSL is not installed on the system. Please install and re-run."
    exit 1
  fi
}

# Function: Check for key files
keyFileCheck() {
  echo "------------------------------------------"
  echo
  if [[ ! -f "$PRIVATE_KEY" ]]; then
    echo "Private key ($PRIVATE_KEY) not found."
    echo "Generating using:"
    echo "openssl genpkey -algorithm RSA -out $PRIVATE_KEY -pkeyopt rsa_keygen_bits:2048"
    openssl genpkey -algorithm RSA -out $PRIVATE_KEY -pkeyopt rsa_keygen_bits:2048
  else
    echo "Private key found, skipping generation."
  fi

  if [[ ! -f "$PUBLIC_KEY" ]]; then
    echo "Public key ($PUBLIC_KEY) not found."
    echo "Generating using:"
    echo "openssl rsa -in $PRIVATE_KEY -pubout -out $PUBLIC_KEY"
    openssl rsa -in $PRIVATE_KEY -pubout -out $PUBLIC_KEY
  else
    echo "Public keypair found, skipping generation."
  fi

  echo "Generating JWK Set from the $PUBLIC_KEY public key for use when setting up the Trusted JWT Issuer"
  ./pem_to_jwk_set.sh
}

# Function: Base64URL encode
base64url_encode() {
  openssl base64 -e -A | tr '+/' '-_' | tr -d '='
}

# Function: Generate signed JWT
genJWT() {
  echo "------------------------------------------"
  echo
  NOW=$(date +%s)
  EXP=$((NOW + 10)) # 10 seconds from now.
  HEADER=$(jq -nc --arg alg "RS256" --arg typ "JWT" '{alg: $alg, typ: $typ}')
  PAYLOAD=$(jq -nc \
    --arg iss "$CLIENT_ID" \
    --arg sub "$SUB" \
    --arg aud "$TOKEN_URL" \
    --argjson iat "$NOW" \
    --argjson exp "$EXP" \
    --arg scope_val "$SCOPE" \
    '{
      iss: $iss,
      sub: $sub,
      aud: $aud,
      iat: $iat,
      exp: $exp,
      scope: [$scope_val]
    }')

  HEADER_B64=$(echo -n "$HEADER" | base64url_encode)
  PAYLOAD_B64=$(echo -n "$PAYLOAD" | base64url_encode)
  UNSIGNED="$HEADER_B64.$PAYLOAD_B64"

  SIGNATURE=$(echo -n "$UNSIGNED" | openssl dgst -sha256 -sign "$PRIVATE_KEY" | base64url_encode)
  JWT="$UNSIGNED.$SIGNATURE"

  echo "Signed JWT:"
  echo "$JWT"
}

#  Function: Decode JWT payload
decodeJWT() {
  echo "------------------------------------------"
  echo
  echo "Decoding ${1} token:"
  jq -R 'split(".") | .[1] | @base64d | fromjson' <<<"${2}"
}

#  Function: Request Access Token
getAccessToken() {
  echo "------------------------------------------"
  echo
  echo "Requesting access token using JWT..."
  RESPONSE=$(curl -s --request POST "$TOKEN_URL" \
    --data "client_id=$CLIENT_ID" \
    --data "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \
    --data "assertion=$JWT" \
    --data "scope=$SCOPE")

  ACCESS_TOKEN=$(echo $RESPONSE | jq -r .access_token)

  if [[ -z "$ACCESS_TOKEN" ]]; then
    echo "Error: access_token not found in response."
    echo "Response: $RESPONSE"
    exit 1
  fi
  echo "Access token generated:"
  echo "$ACCESS_TOKEN"
}

# Main
openSSLCheck
keyFileCheck
setup
genJWT
decodeJWT "Signed JWT" $JWT
getAccessToken
decodeJWT Access $ACCESS_TOKEN