package routes

import (
	"ecommerce/controllers"
	"github.com/gin-gonic/gin"
)

func UserRoutes(incomingRoutes *gin.Engine) {

	incomingRoutes.POST("/users/signup", controllers.SignUp())
	incomingRoutes.POST("/users/login", controllers.Login())
	incomingRoutes.POST("/admin/addproduct", controllers.ProductViewerAdmin())
	incomingRoutes.GET("/users/productview", controllers.SearchProduct())
	incomingRoutes.GET("/users/search", controllers.SearchProductByQuery())
	incomingRoutes.GET("/callback", controllers.Callback()) //google_login
	incomingRoutes.GET("/google_login", controllers.GoogleLogin())
	incomingRoutes.GET("/encryption", controllers.Encryption())
	incomingRoutes.GET("/GenerateCookie", controllers.GenerateCookie())
}
