#!/bin/bash

# Config parameters to modify
SUB="cde373a9-51ee-41e2-bdfe-624cfdc02514" #This should be the _id value of the user
CLIENT_ID="salesforce_client"
PRIVATE_KEY="private_key.pem"
PUBLIC_KEY="public_key.pem"
TENANT="openam-XXXX"
REALM="alpha"

# No need to modify these config parameters
IDM_ENDPOINT="https://${TENANT}/openidm/managed/${REALM}_user?_fields=userName,givenName,sn,mail,accountStatus&_prettyPrint=true&_queryFilter=true&_pageSize=1"
TOKEN_URL="https://${TENANT}:443/am/oauth2/realms/root/realms/${REALM}/access_token"
SCOPE="fr:idm:*"
NOW=$(date +%s)
EXP=$((NOW + 300)) # 5 minutes from now

# Function: Setup Guidance 
setup() {
  cat <<EOF
------------------------------------------

User and Delegated Admin Setup
------------------------------------------
1. Create a new user via the Platform UI
2. Create an internal delegated admin role, set required CRUD permissions for alpha_user, and add the user to this role
3. From the Platform UI note the _id value of the user and update the SUB variable in this script

OAuth2 Client Setup
------------------------------------------
1. Create a Native/SPA Public OAuth2 client called $CLIENT_ID
2. Set Grant Types to JWT Bearer only
3. Set Scopes to $SCOPE only
4. Advanced Settings > Access: Set Response Types to token
5. Advanced Settings > Authentication: Set Token Endpoint Auth Method to client_secret_post

Trusted JWT Issuer Setup
------------------------------------------
1. In Access Management UI > Applications > Trusted JWT Issuer > Add Trusted JWT Issuer Agent
2. Name it: myJWTAgent
3. Set JWT Issuer to: $CLIENT_ID
4. Convert $PUBLIC_KEY to a JWK Set and paste it in the config
5. Set Allowed Subjects to: $SUB
EOF

  read -n1 -r -p "Press 'q' to quit and complete setup manually, or any other key to continue: " key
  echo
  if [[ "$key" =~ [qQ] ]]; then
    echo "Exiting setup..."
    exit 0
  fi
}

# Function: Check for key files 
keyFileCheck() {
  echo "------------------------------------------"
  echo
  [[ ! -f "$PRIVATE_KEY" ]] && {
    echo "Private key ($PRIVATE_KEY) not found."
    echo "Generate using:"
    echo "openssl genpkey -algorithm RSA -out $PRIVATE_KEY -pkeyopt rsa_keygen_bits:2048"
    exit 1
  }
  [[ ! -f "$PUBLIC_KEY" ]] && {
    echo "Public key ($PUBLIC_KEY) not found."
    echo "Generate using:"
    echo "openssl rsa -in $PRIVATE_KEY -pubout -out $PUBLIC_KEY"
    exit 1
  }
  echo "Public and private keypair found."
}

# Function: Base64URL encode 
base64url_encode() {
  openssl base64 -e -A | tr '+/' '-_' | tr -d '='
}

# Function: Generate signed JWT 
genJWT() {
  echo "------------------------------------------"
  echo

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
  echo "Decoded JWT Payload:"
  jq -R 'split(".") | .[1] | @base64d | fromjson' <<< "$JWT"
}

#  Function: Request Access Token 
getAccessToken() {
  echo "------------------------------------------"
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

callIDM() {
	echo "------------------------------------------"
	echo "Calling this IDM Endpoint: ${IDM_ENDPOINT} in realm: ${REALM} to read the first user in the repo using generated access token:"
	curl -s \
		--request GET \
		--header 'Authorization: Bearer '${ACCESS_TOKEN}'' \
		${IDM_ENDPOINT} | jq .

}

# Main
setup
keyFileCheck
genJWT
decodeJWT
getAccessToken
callIDM