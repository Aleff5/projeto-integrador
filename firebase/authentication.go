package firebase

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	"firebase.google.com/go/v4/auth"
)

// Criar usuário
func CreateFirebaseUser(email, password, displayName string) (*auth.UserRecord, error) {
	ctx := context.Background()
	client := GetAuthClient()

	params := (&auth.UserToCreate{}).
		Email(email).
		EmailVerified(false).
		Password(password).
		DisplayName(displayName).
		Disabled(false)

	user, err := client.CreateUser(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("erro ao criar usuário: %v", err)
	}

	log.Printf("Usuário criado com sucesso: UID = %s\n", user.UID)
	return user, nil
}

// Buscar usuário por UID
func GetUserByUID(uid string) (*auth.UserRecord, error) {
	ctx := context.Background()
	client := GetAuthClient()

	user, err := client.GetUser(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("erro ao buscar usuário: %v", err)
	}

	return user, nil
}

// Buscar usuário por e-mail
func GetUserByEmail(email string) (*auth.UserRecord, error) {
	ctx := context.Background()
	client := GetAuthClient()

	user, err := client.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("erro ao buscar usuário por e-mail: %v", err)
	}

	return user, nil
}

// Deletar usuário
func DeleteUser(uid string) error {
	ctx := context.Background()
	client := GetAuthClient()

	err := client.DeleteUser(ctx, uid)
	if err != nil {
		return fmt.Errorf("erro ao deletar usuário: %v", err)
	}

	log.Printf("Usuário com UID %s deletado com sucesso\n", uid)
	return nil
}

func VerifyUserToken(token string) (*auth.Token, error) {
	ctx := context.Background()
	client := GetAuthClient()

	verifiedToken, err := client.VerifyIDToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("erro ao verificar token: %v", err)
	}

	return verifiedToken, nil

}

func CheckOrCreateUserInPostgres(db *sql.DB, token *auth.Token) (string, error) {
	// Recupera dados do token
	uid := token.UID
	email, _ := token.Claims["email"].(string)
	displayName, _ := token.Claims["name"].(string)

	// Verifica se o UID já existe no banco
	var dbUID string
	err := db.QueryRow("SELECT firebase_uid FROM users WHERE firebase_uid = $1", uid).Scan(&dbUID)

	switch {
	case err == sql.ErrNoRows:
		// Usuário não encontrado - cria novo registro
		log.Printf("Primeiro acesso para UID %s. Criando no PostgreSQL...", uid)
		_, insertErr := db.Exec(
			"INSERT INTO users (firebase_uid, email, display_name) VALUES ($1, $2, $3)",
			uid, email, displayName,
		)
		if insertErr != nil {
			log.Printf("Erro ao inserir usuário no DB: %v", insertErr)
			return "", fmt.Errorf("erro ao inserir usuário no DB: %v", insertErr)
		}
		// Retorna o UID
		return uid, nil

	case err != nil:
		// Outro erro
		log.Printf("Erro ao buscar usuário no DB: %v", err)
		return "", fmt.Errorf("erro ao buscar usuário no DB: %v", err)

	default:
		// Usuário já existe
		log.Printf("Usuário %s encontrado no PostgreSQL", uid)
		return dbUID, nil
	}
}
