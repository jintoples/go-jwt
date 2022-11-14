package main

import (
	"os"

	"github.com/gin-gonic/gin"
	route "github.com/jintoples/go-jwt/routes"
)

func main() {
	port := os.Getenv("PORT")

	if port == "" {
		port = "8080"
	}

	router := gin.New()
	router.Use(gin.Logger())

	route.AuthRoutes(router)
	route.UserRoutes(router)

	router.GET("/api-1", func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{"success": "Access granted for api 1"})
	})

	router.GET("/api-2", func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{"success": "Access granted for api 2"})
	})

	router.Run(":" + port)
}
