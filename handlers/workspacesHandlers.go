package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"projeto-integrador/models"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

func CreateWorkspaceHandler(w http.ResponseWriter, r *http.Request) {
	// Pega o UID do contexto (setado no middleware de autenticação)
	uid := r.Context().Value("userUID")
	if uid == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Decodifica o JSON recebido
	var workspace models.Workspace
	err := json.NewDecoder(r.Body).Decode(&workspace)
	if err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Validações básicas
	if workspace.Name == "" {
		http.Error(w, "Name is required", http.StatusBadRequest)
		return
	}

	// Insere no banco
	query := `
		INSERT INTO workspaces (name, description, is_public, owner_uid, created_at)
		VALUES ($1, $2, $3, $4, NOW())
		RETURNING id, created_at
	`

	err = db.QueryRow(
		query,
		workspace.Name,
		workspace.Description,
		workspace.IsPublic,
		uid,
	).Scan(&workspace.ID, &workspace.CreatedAt)

	if err != nil {
		log.Printf("Erro ao criar workspace: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	workspace.OwnerUID = uid.(string)

	// Retorna o workspace criado
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(workspace)
}

// getWorkspaceHandler retorna os detalhes de um workspace específico
func getWorkspaceHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	workspaceID := vars["id"]

	// Obter UID do usuário a partir do token Firebase
	uid, err := getUIDFromToken(r)
	if err != nil {
		http.Error(w, "Não autorizado", http.StatusUnauthorized)
		return
	}

	// Verificar se o usuário é membro do workspace
	isMember, err := isWorkspaceMember(uid, workspaceID)
	if err != nil || !isMember {
		http.Error(w, "Acesso não autorizado ao workspace", http.StatusForbidden)
		return
	}
	// Verificar se o workspace existe
	var exists bool
	var workspace models.Workspace
	query := `SELECT id, name, description, privado, dono_id, created_at 
              FROM workspaces WHERE id = $1`
	err = db.QueryRow(query, workspaceID).Scan(
		&workspace.ID, &workspace.Name, &workspace.Description,
		&workspace.IsPrivate, &workspace.OwnerID, &workspace.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Workspace não encontrado", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(workspace)
}

// updateWorkspaceHandler atualiza um workspace existente
func updateWorkspaceHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	workspaceID := vars["id"]

	// Obter UID do usuário a partir do token Firebase
	uid, err := getUIDFromToken(r)
	if err != nil {
		http.Error(w, "Não autorizado", http.StatusUnauthorized)
		return
	}

	// Verificar se o usuário é dono do workspace
	isOwner, err := isWorkspaceOwner(uid, workspaceID)
	if err != nil || !isOwner {
		http.Error(w, "Somente o dono pode atualizar o workspace", http.StatusForbidden)
		return
	}

	var updates struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		IsPrivate   *bool   `json:"is_private"`
	}

	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Construir query dinâmica baseada nos campos fornecidos
	query := "UPDATE workspaces SET "
	params := []interface{}{}
	paramCount := 1

	if updates.Name != nil {
		query += fmt.Sprintf("name = $%d, ", paramCount)
		params = append(params, *updates.Name)
		paramCount++
	}

	if updates.Description != nil {
		query += fmt.Sprintf("description = $%d, ", paramCount)
		params = append(params, *updates.Description)
		paramCount++
	}

	if updates.IsPrivate != nil {
		query += fmt.Sprintf("privado = $%d, ", paramCount)
		params = append(params, *updates.IsPrivate)
		paramCount++
	}

	// Remover a vírgula final e adicionar a cláusula WHERE
	query = strings.TrimSuffix(query, ", ") + " WHERE id = $" + strconv.Itoa(paramCount)
	params = append(params, workspaceID)

	_, err = db.Exec(query, params...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// deleteWorkspaceHandler remove um workspace
func deleteWorkspaceHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	workspaceID := vars["id"]

	// Obter UID do usuário a partir do token Firebase
	uid, err := getUIDFromToken(r)
	if err != nil {
		http.Error(w, "Não autorizado", http.StatusUnauthorized)
		return
	}

	// Verificar se o usuário é dono do workspace
	isOwner, err := isWorkspaceOwner(uid, workspaceID)
	if err != nil || !isOwner {
		http.Error(w, "Somente o dono pode deletar o workspace", http.StatusForbidden)
		return
	}

	// Usar transação para garantir integridade ao deletar workspace e relacionamentos
	tx, err := db.Begin()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	// Deletar membros primeiro por causa da FK
	_, err = tx.Exec("DELETE FROM membros_workspace WHERE workspace_id = $1", workspaceID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Deletar tarefas relacionadas
	_, err = tx.Exec("DELETE FROM tarefas WHERE workspace_id = $1", workspaceID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Finalmente deletar o workspace
	_, err = tx.Exec("DELETE FROM workspaces WHERE id = $1", workspaceID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err = tx.Commit(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// addMemberHandler adiciona um usuário como membro de um workspace
func addMemberHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	workspaceID := vars["id"]

	// Obter UID do usuário a partir do token Firebase
	uid, err := getUIDFromToken(r)
	if err != nil {
		http.Error(w, "Não autorizado", http.StatusUnauthorized)
		return
	}

	// Verificar se o usuário tem permissão para adicionar membros (dono ou admin)
	hasPermission, err := canManageWorkspaceMembers(uid, workspaceID)
	if err != nil || !hasPermission {
		http.Error(w, "Sem permissão para adicionar membros", http.StatusForbidden)
		return
	}

	var member struct {
		UserID int    `json:"user_id"`
		Role   string `json:"role"`
	}

	if err := json.NewDecoder(r.Body).Decode(&member); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validar role
	if member.Role != "admin" && member.Role != "member" {
		http.Error(w, "Role inválida", http.StatusBadRequest)
		return
	}

	// Verificar se o usuário existe
	var userExists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)", member.UserID).Scan(&userExists)
	if err != nil || !userExists {
		http.Error(w, "Usuário não encontrado", http.StatusBadRequest)
		return
	}

	// Verificar se o usuário já é membro
	var alreadyMember bool
	err = db.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM membros_workspace WHERE usuario_id = $1 AND workspace_id = $2)",
		member.UserID, workspaceID,
	).Scan(&alreadyMember)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if alreadyMember {
		http.Error(w, "Usuário já é membro deste workspace", http.StatusConflict)
		return
	}

	// Adicionar membro
	_, err = db.Exec(
		"INSERT INTO membros_workspace (usuario_id, workspace_id, role) VALUES ($1, $2, $3)",
		member.UserID, workspaceID, member.Role,
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// removeMemberHandler remove um usuário de um workspace
func removeMemberHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	workspaceID := vars["id"]
	userID := vars["user_id"]

	// Obter UID do usuário a partir do token Firebase
	uid, err := getUIDFromToken(r)
	if err != nil {
		http.Error(w, "Não autorizado", http.StatusUnauthorized)
		return
	}

	// Verificar se o usuário tem permissão para remover membros (dono ou admin)
	hasPermission, err := canManageWorkspaceMembers(uid, workspaceID)
	if err != nil || !hasPermission {
		http.Error(w, "Sem permissão para remover membros", http.StatusForbidden)
		return
	}

	// Verificar se o usuário sendo removido é o dono
	var isOwner bool
	err = db.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM workspaces WHERE id = $1 AND dono_id = $2)",
		workspaceID, userID,
	).Scan(&isOwner)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if isOwner {
		http.Error(w, "Não é possível remover o dono do workspace", http.StatusForbidden)
		return
	}

	// Remover membro
	result, err := db.Exec(
		"DELETE FROM membros_workspace WHERE usuario_id = $1 AND workspace_id = $2",
		userID, workspaceID,
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if rowsAffected == 0 {
		http.Error(w, "Membro não encontrado no workspace", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// listWorkspaceMembersHandler lista todos os membros de um workspace
func listWorkspaceMembersHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	workspaceID := vars["id"]

	// Obter UID do usuário a partir do token Firebase
	uid, err := getUIDFromToken(r)
	if err != nil {
		http.Error(w, "Não autorizado", http.StatusUnauthorized)
		return
	}

	// Verificar se o usuário é membro do workspace
	isMember, err := isWorkspaceMember(uid, workspaceID)
	if err != nil || !isMember {
		http.Error(w, "Acesso não autorizado ao workspace", http.StatusForbidden)
		return
	}

	rows, err := db.Query(`
        SELECT u.id, u.username, u.email, m.role, m.joined_at 
        FROM membros_workspace m
        JOIN users u ON m.usuario_id = u.id
        WHERE m.workspace_id = $1
        ORDER BY m.joined_at DESC
    `, workspaceID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	members := []map[string]interface{}{}
	for rows.Next() {
		var member struct {
			ID       int       `json:"id"`
			Username string    `json:"username"`
			Email    string    `json:"email"`
			Role     string    `json:"role"`
			JoinedAt time.Time `json:"joined_at"`
		}
		if err := rows.Scan(&member.ID, &member.Username, &member.Email, &member.Role, &member.JoinedAt); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		members = append(members, map[string]interface{}{
			"user_id":   member.ID,
			"username":  member.Username,
			"email":     member.Email,
			"role":      member.Role,
			"joined_at": member.JoinedAt,
		})
	}

	json.NewEncoder(w).Encode(members)
}

// Funções auxiliares
func getUIDFromToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("token não fornecido")
	}

	token := authHeader[len("Bearer "):]
	decodedToken, err := authClient.VerifyIDToken(context.Background(), token)
	if err != nil {
		return "", fmt.Errorf("token inválido")
	}

	return decodedToken.UID, nil
}

func isWorkspaceMember(uid string, workspaceID string) (bool, error) {
	var userID int
	err := db.QueryRow("SELECT id FROM users WHERE firebase_uid = $1", uid).Scan(&userID)
	if err != nil {
		return false, err
	}

	var isMember bool
	err = db.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM membros_workspace WHERE usuario_id = $1 AND workspace_id = $2)",
		userID, workspaceID,
	).Scan(&isMember)
	return isMember, err
}

func isWorkspaceOwner(uid string, workspaceID string) (bool, error) {
	var userID int
	err := db.QueryRow("SELECT id FROM users WHERE firebase_uid = $1", uid).Scan(&userID)
	if err != nil {
		return false, err
	}

	var isOwner bool
	err = db.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM workspaces WHERE id = $1 AND dono_id = $2)",
		workspaceID, userID,
	).Scan(&isOwner)
	return isOwner, err
}

func canManageWorkspaceMembers(uid string, workspaceID string) (bool, error) {
	var userID int
	err := db.QueryRow("SELECT id FROM users WHERE firebase_uid = $1", uid).Scan(&userID)
	if err != nil {
		return false, err
	}

	// Verificar se é dono
	var isOwner bool
	err = db.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM workspaces WHERE id = $1 AND dono_id = $2)",
		workspaceID, userID,
	).Scan(&isOwner)
	if err != nil {
		return false, err
	}
	if isOwner {
		return true, nil
	}

	// Verificar se é admin
	var isAdmin bool
	err = db.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM membros_workspace WHERE usuario_id = $1 AND workspace_id = $2 AND role = 'admin')",
		userID, workspaceID,
	).Scan(&isAdmin)
	return isAdmin, err
}
