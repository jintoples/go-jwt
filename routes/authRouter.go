package routes

import (
	"github.com/gin-gonic/gin"
	controller "github.com/jintoples/go-jwt/controllers"
)

func AuthRoutes(incominRoutes *gin.Engine) {
	incominRoutes.POST("/users/signup", controller.Signup())
	incominRoutes.POST("/users/login", controller.Login())
}
