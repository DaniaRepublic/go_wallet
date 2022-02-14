package jwt

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"wallet_server/classes"

	"github.com/golang-jwt/jwt"
)

var (
	jwtKey = []byte(os.Getenv("JWT_SECRET"))
)

type authClaims struct {
	jwt.StandardClaims
	ID int
}

func GenerateAPNsToken(iat int64) (string, error) {
	token := jwt.New(jwt.SigningMethodES256)
	delete(token.Header, "typ")
	token.Header["kid"] = "YW62WL57MX"

	claims := token.Claims.(jwt.MapClaims)
	claims["iss"] = "G63G4WSKWU"
	claims["iat"] = iat
	projectDir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	pemCert, err := os.ReadFile(projectDir + "/Key.pem")
	if err != nil {
		return "", err
	}
	privKey, err := jwt.ParseECPrivateKeyFromPEM(pemCert)
	if err != nil {
		return "", err
	}
	tokenStr, err := token.SignedString(privKey)
	if err != nil {
		return "", err
	}

	return tokenStr, nil
}

func GenerateToken(u classes.User, ttl int) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, authClaims{
		StandardClaims: jwt.StandardClaims{
			Subject:   u.Name + strconv.Itoa(u.ID),
			ExpiresAt: time.Now().Add(time.Second * time.Duration(ttl)).Unix(),
		},
		ID: u.ID,
	})

	tokenStr, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}

	return tokenStr, nil
}

func validateToken(tokenStr string) (string, error) {
	var claims authClaims
	token, err := jwt.ParseWithClaims(tokenStr, &claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	})
	if err != nil {
		return "", err
	}

	if !token.Valid {
		return "", errors.New("invalid token")
	}

	return claims.Subject, nil
}
