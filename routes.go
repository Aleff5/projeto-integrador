package main

import (
	"log"
	"net/http"
	"projeto-integrador/handlers"

	gorillahandlers "github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

func LoadRoutes() {
	r := mux.NewRouter()

	r.HandleFunc("/register", handlers.RegisterHandler)
	// r.HandleFunc("/login", handlers.LoginHandler)
	// r.HandleFunc("/user", handlers.AuthMiddleware(handlers.UserHandler))
	// r.HandleFunc("/delete", handlers.AuthMiddleware(handlers.DeleteUserHandler))
	// r.HandleFunc("/update", handlers.AuthMiddleware(handlers.UpdateUserHandler))
	// r.HandleFunc("/getuser", handlers.AuthMiddleware(handlers.GetUserHandler))
	// r.HandleFunc("/getallusers", handlers.AuthMiddleware(handlers.GetAllUsersHandler))

	headers := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization"})
	methods := handlers.AllowedMethods([]string{"GET", "POST", "PUT"})

	headers := gorillahandlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization"})
	methods := gorillahandlers.AllowedMethods([]string{"GET", "POST", "PUT"})
	origins := gorillahandlers.AllowedOrigins([]string{"*"})

	log.Fatal(http.ListenAndServe(":8080", gorillahandlers.CORS(headers, methods, origins)(r)))
	log.Fatal(http.ListenAndServe(":8080", nil))
}
