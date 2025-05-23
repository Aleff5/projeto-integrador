package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"projeto-integrador/database"
	"projeto-integrador/models"
	"time"
)

func CreateWorkspaceHandler(w http.ResponseWriter, r *http.Request) {
	uid := r.Context().Value("userUID")
	if uid == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Decodifica o JSON recebido
	var workspace models.Workspace
	if err := json.NewDecoder(r.Body).Decode(&workspace); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Validações básicas
	if workspace.Name == "" {
		http.Error(w, "Workspace name is required", http.StatusBadRequest)
		return
	}

	db, err := database.ConnectPostgres()
	if err != nil {
		log.Printf("Error connecting to database: %v", err)
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}
	// defer db.Close()
	// Query para criar o workspace
	query := `
		INSERT INTO workspaces (name, description, is_public, owner_uid, created_at)
		VALUES ($1, $2, $3, $4, NOW())
		RETURNING id, created_at
	`

	var createdAt time.Time
	err = db.QueryRow(
		query,
		workspace.Name,
		workspace.Description,
		workspace.IsPublic,
		uid,
	).Scan(&workspace.ID, &createdAt)

	if err != nil {
		log.Printf("Error creating workspace: %v", err)
		http.Error(w, "Database error while creating workspace", http.StatusInternalServerError)
		return
	}

	workspace.OwnerUID = uid.(string)
	workspace.CreatedAt = createdAt
	workspace.Members = 1 // Criador é o primeiro membro

	// Adiciona o criador na tabela user_workspace como admin
	_, err = db.Exec(`
		INSERT INTO user_workspace (workspace_id, user_id, role, joined_at)
		VALUES ($1, $2, 'admin', NOW())
	`, workspace.ID, uid)

	if err != nil {
		log.Printf("Error adding user to user_workspace: %v", err)
		http.Error(w, "Database error while adding user to workspace", http.StatusInternalServerError)
		return
	}

	// Retorna o workspace criado
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(workspace)
}
