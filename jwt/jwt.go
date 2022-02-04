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

var jwtKey = []byte(os.Getenv("JWT_SECRET"))

type authClaims struct {
	jwt.StandardClaims
	ID int
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

func validateToken(tokenStr string) (string, int, error) {
	var claims authClaims
	token, err := jwt.ParseWithClaims(tokenStr, &claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	})
	if err != nil {
		return "", -1, err
	}

	if !token.Valid {
		return "", -1, errors.New("invalid token")
	}

	return claims.Subject, claims.ID, nil
}
