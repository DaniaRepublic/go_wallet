package authentication

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

var (
	W_AUTH_HEADER = os.Getenv("W_AUTH_HEADER") // wallet secret
	S_AUTH_HEADER = os.Getenv("S_AUTH_HEADER") // scanner secret
	P_AUTH_HEADER = os.Getenv("P_AUTH_HEADER") // payment system secret
)

func VerifyWalletAuthHeader() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader != W_AUTH_HEADER {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}
}

func VerifyScannerAuthHeader() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader != S_AUTH_HEADER {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}
}

func VerifyPaymentSystemAuthHeader() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader != P_AUTH_HEADER {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}
}
