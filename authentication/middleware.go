package authentication

import (
	"os"

	"github.com/gin-gonic/gin"
)

var AUTH_HEADER = os.Getenv("AUTH_HEADER")

func VerifyAuthHeader() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader != AUTH_HEADER {
			c.AbortWithStatus(401)
			return
		}
		c.Next()
	}
}
