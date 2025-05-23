package firebase

import (
	"context"
	"fmt"
	"log"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"google.golang.org/api/option"
)

func InitializeFirebase() (*firebase.App, error) {
	opt := option.WithCredentialsFile("firebase/testes-a5a53-firebase-adminsdk-fbsvc-4dc021ae4e.json")

	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		log.Fatalf("Erro ao inicializar Firebase: %v", err)
	}

	fmt.Println("Firebase inicializado com sucesso!")
	return app, nil
}

// retorna o cliente de autenticação
func GetAuthClient() *auth.Client {
	ctx := context.Background()
	app, err := InitializeFirebase()
	if err != nil {
		log.Fatalf("Erro ao inicializar Firebase: %v", err)
	}
	// Obter o cliente de autenticação
	authClient, err := app.Auth(ctx)
	if err != nil {
		log.Fatalf("Erro ao obter cliente de Auth: %v", err)
	}
	return authClient
}
