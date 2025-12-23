package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// HashPassword takes a plain text password and returns an argon2id hash
func HashPassword(password string) (string, error) {
	// Validate password is not empty
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}

	// Create hash with default parameters
	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	return hash, nil
}

// CheckPasswordHash compares a plain text password with an argon2id hash
func CheckPasswordHash(password, hash string) (bool, error) {
	// Validate inputs
	if password == "" {
		return false, fmt.Errorf("password cannot be empty")
	}
	if hash == "" {
		return false, fmt.Errorf("hash cannot be empty")
	}

	// Compare password with hash
	match, err := argon2id.ComparePasswordAndHash(password, hash)
	if err != nil {
		return false, fmt.Errorf("failed to compare password and hash: %w", err)
	}

	return match, nil
}

// IsPasswordHashed checks if a string appears to be an argon2id hash
func IsPasswordHashed(str string) bool {
	// Argon2id hashes typically start with $argon2id$v=19$...
	return strings.HasPrefix(str, "$argon2id$")
}


func MakeJWT(userID uuid.UUID,tokenSecret string,expiresIn time.Duration)(string,error){

    //information inside the jwt
	//create the claims
	claims:=jwt.RegisteredClaims{
		Issuer: "chirpy",
		IssuedAt: jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt:jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)),
		Subject: userID.String(),
	}

	//create a new token with the claims and data to be included in the token 
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,claims)

	//sign the token with the secret key(must be []byte for HS256) //so the token needs to be signed like being approaved
	signedToken,err:=token.SignedString([]byte(tokenSecret))//converts the tokesecret to bytes as required by the signing method
	if err!= nil{
		return "",err
	}
	return signedToken,nil
}

//validate JWT validates a JWT AND RETURNS THE USER ID IF VALID
func ValidateJWT(tokenString,tokenSecret string)(uuid.UUID,error){
	//parse and validate the token
	token,err:=jwt.ParseWithClaims(
		tokenString,
		&jwt.RegisteredClaims{},
		func(token *jwt.Token)(interface{},error){
			//verify the signing method
			if _,ok:= token.Method.(*jwt.SigningMethodHMAC); !ok{
				return nil,errors.New("unexpected signing method")
			}
			return []byte(tokenSecret), nil
		},
	)

	if err !=nil{
		return uuid.Nil,err
	}

	//extract the claims
	claims,ok:=token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid{
		return uuid.Nil,errors.New("invalid token claims")
	}

	//parse the user ID from the subject field
	userID, err:=uuid.Parse(claims.Subject)
	if err!= nil{
		return uuid.Nil,err
	}
	return userID,nil
}


func GetBearerToken(headers http.Header)(string,error){
authHeader:=headers.Get("Authorization")
if authHeader ==""{
	return "",errors.New("authorization header not found")
}

//check if it starts with Bearer
if !strings.HasPrefix(authHeader,"Bearer "){
	return "",errors.New("invalid authorization header format")
}

//extract token by removing "Bearer " prefix and trimming whitespace
token:=strings.TrimSpace(strings.TrimPrefix(authHeader,"Bearer"))
if token ==""{
	return "",errors.New("token is empty")
}

return token,nil
}

func MakeRefreshToken()(string,error){
    //create a 32 byte slice
	b:=make([]byte,32)

	//fill it with random data
	_, err:=rand.Read(b)
	if err !=nil{
		return "",err
	}
	//convvert to hex string
	return hex.EncodeToString(b),nil
    }


	