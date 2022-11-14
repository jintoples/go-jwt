package routes

import (
	"github.com/gin-gonic/gin"
	controller "github.com/jintoples/go-jwt/controllers"
	"github.com/jintoples/go-jwt/middleware"
)

func UserRoutes(incominRoutes *gin.Engine) {
	incominRoutes.Use(middleware.Authenticate())
	incominRoutes.GET("/users", controller.GetUsers())
	incominRoutes.GET("/users/:user_id", controller.GetUser())
}
