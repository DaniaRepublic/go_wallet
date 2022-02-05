package jwt

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func VerifyToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := c.Cookie("JWTAuth")
		if err != nil {
			c.Redirect(http.StatusFound, "/login")
			//c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			//	"error no JWTAuth cookie": err,
			//})
		}

		name, err := validateToken(token)
		if err != nil {
			c.Redirect(http.StatusFound, "/login")
			//c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			//	"error cookie JWTAuth invalid": err,
			//})
		}
		c.Set("name", name)

		c.Next()
	}
}
