package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"projeto-integrador/database"
	"projeto-integrador/firebase"
	"projeto-integrador/models"
	"strings"
	
	"firebase.google.com/go/v4/auth"
)

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Pega o token do header Authorization
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Verifica o token com Firebase
		verifiedToken, err := firebase.VerifyUserToken(tokenString)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Coloca o UID no contexto da requisição
		ctx := context.WithValue(r.Context(), "userUID", verifiedToken.UID)

		// Segue para o próximo handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	// Parse do corpo JSON
	var user models.Usuario
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Verificar se o usuário já existe no Firebase pelo email
	ctx := context.Background()
	authClient := firebase.GetAuthClient()

	_, err = authClient.GetUserByEmail(ctx, user.Email)
	if err == nil {
		// Usuário já existe
		http.Error(w, "User already exists", http.StatusConflict)
		return

	} else if auth.IsUserNotFound(err) {
		// OK, usuário não existe, pode criar
		// Cria no Firebase
		params := (&auth.UserToCreate{}).
			Email(user.Email).
			Password(user.Password).
			DisplayName(user.DisplayName).
			Disabled(false)

		firebaseUser, createErr := authClient.CreateUser(ctx, params)
		if createErr != nil {
			http.Error(w, "Failed to create user in Firebase", http.StatusInternalServerError)
			return
		}

		// Agora salva no PostgreSQL, se desejar
		db, err := database.ConnectPostgres()
		if err != nil {
			http.Error(w, "Failed to connect to database", http.StatusInternalServerError)
			return
		}
		_, insertErr := db.Exec(
			"INSERT INTO users (firebase_uid, email, display_name) VALUES ($1, $2, $3)",
			firebaseUser.UID, user.Email, user.DisplayName,
		)
		if insertErr != nil {
			http.Error(w, "Failed to save user in database", http.StatusInternalServerError)
			return
		}
		defer db.Close()

		// Aqui você pode criar um workspace privado para o usuário
		models.CreatePrivateWorkspace(db, firebaseUser.UID)

		// ** PASSO CHAVE: Gerar Custom Token para o Frontend **
		customToken, tokenErr := authClient.CustomToken(ctx, firebaseUser.UID)
		if tokenErr != nil {
			log.Printf("Erro ao gerar custom token para UID %s: %v", firebaseUser.UID, tokenErr)
			// Adicionar lógica de rollback para o usuário no Firebase e DB
			http.Error(w, "Failed to generate authentication token", http.StatusInternalServerError)
			return
		}

		log.Printf("Custom token gerado para UID %s", firebaseUser.UID)

		// Resposta de sucesso para o frontend
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json") // Definir Content-Type
		json.NewEncoder(w).Encode(map[string]string{
			"message":     "User created successfully and ready to sign in",
			"uid":         firebaseUser.UID, // Opcional, mas pode ser útil
			"customToken": customToken,      // <--- Envie o Custom Token!
		})
		return
	} else {
		// Outro erro inesperado
		log.Printf("Erro ao buscar usuário no Firebase: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Suponha que o UID venha do contexto (middleware de autenticação)
	uid := r.Context().Value("userUID")
	if uid == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Obter o client do Firebase
	ctx := context.Background()
	authClient := firebase.GetAuthClient()

	// Revogar os tokens de refresh do usuário
	err := authClient.RevokeRefreshTokens(ctx, uid.(string))
	if err != nil {
		log.Printf("Erro ao revogar tokens: %v", err)
		http.Error(w, "Erro ao fazer logout", http.StatusInternalServerError)
		return
	}

	log.Printf("Tokens revogados para UID: %s", uid)

	// Opcional: remover cookies/sessões locais, se estiver usando cookies HTTP-only
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1, // expira imediatamente
	})

	// Retorna sucesso
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Logout efetuado com sucesso",
	})
}

func DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	// Handle delete user logic
}

func SocialLoginHandler(w http.ResponseWriter, r *http.Request) {
	// Handle social login logic
}
