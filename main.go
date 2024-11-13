package main

import (
	"api-crud-go/auth"
	"api-crud-go/database"
	"api-crud-go/handlers"
	"api-crud-go/models"
	"net/http"

	"github.com/gin-gonic/gin"
)

var users = []models.User{
	{ID: "1", Username: "user1", Password: "password", Role: "user"},
	{ID: "2", Username: "admin1", Password: "password", Role: "admin"},
}

func main() {
	dsn := "root:admin@tcp(127.0.0.1:3306)/library_management"
	database.InitDB(dsn)

	router := gin.Default()

	// Rota para login
	router.POST("/login", func(c *gin.Context) {
		var creds models.User
		if err := c.BindJSON(&creds); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "invalid request"})
			return
		}

		for _, user := range users {
			if user.Username == creds.Username && user.Password == creds.Password {
				token, err := auth.GenerateJWT(user.Username, user.Role)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"message": "could not generate token"})
					return
				}
				c.JSON(http.StatusOK, gin.H{"token": token})
				return
			}
		}

		c.JSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
	})

	// Middleware para validar JWT e controle de acesso baseado em papéis
	authMiddleware := func(role string) gin.HandlerFunc {
		return func(c *gin.Context) {
			tokenStr := c.GetHeader("Authorization")
			claims, err := auth.ValidateJWT(tokenStr)
			if err != nil || claims.Role != role {
				c.JSON(http.StatusForbidden, gin.H{"message": "forbidden"})
				c.Abort()
				return
			}
			c.Next()
		}
	}

	// Rotas públicas
	router.GET("/books", handlers.GetBooks)
	router.GET("/books/:id", handlers.GetBookByID)

	// Rotas protegidas
	userGroup := router.Group("/user")
	userGroup.Use(authMiddleware("user"))
	userGroup.POST("/comments", handlers.PostComment)

	adminGroup := router.Group("/admin")
	adminGroup.Use(authMiddleware("admin"))
	adminGroup.POST("/books", handlers.PostBook)
	adminGroup.PUT("/books/:id", handlers.UpdateBook)
	adminGroup.DELETE("/books/:id", handlers.DeleteBook)

	router.Run("localhost:8080")
}
