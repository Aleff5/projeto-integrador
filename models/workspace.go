package models

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Workspace struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	IsPublic    bool      `json:"is_public"`
	OwnerUID    string    `json:"owner_uid"` // Firebase UID do dono
	CreatedAt   time.Time `json:"created_at"`
	Members     int       `json:"members"`
}

type WorkspaceInvite struct {
	ID          int64      `json:"id"`
	WorkspaceID int64      `json:"workspace_id"`
	InviteCode  string     `json:"invite_code"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"` // ponteiro permite nulo
	Role        string     `json:"role"`
}

// Relação Usuário → Workspace
type UserWorkspace struct {
	WorkspaceID int64     `json:"workspace_id"`
	UserID      string    `json:"user_id"` // Firebase UID
	Role        string    `json:"role"`
	JoinedAt    time.Time `json:"joined_at"`
}

type WorkspaceMember struct {
	UserID      string    `json:"user_id"`
	DisplayName string    `json:"display_name"`
	Email       string    `json:"email"`
	Role        string    `json:"role"`
	JoinedAt    time.Time `json:"joined_at"`
}

func CreatePrivateWorkspace(db *sql.DB, ownerUID string) (*Workspace, error) {
	// Verifica se já existe um workspace privado para esse usuário
	var existingID int64
	err := db.QueryRow(`
	SELECT id FROM workspaces WHERE owner_uid = $1 AND is_public = false
	`, ownerUID).Scan(&existingID)

	if err != nil && err != sql.ErrNoRows {
		return nil, err // Erro de banco real
	}

	if err == nil {
		// Já existe um workspace privado
		return nil, errors.New("private workspace already exists")
	}

	// Inicia uma transação
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() {
		// Rollback se a transação ainda estiver aberta (em caso de erro)
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p)
		} else if err != nil {
			tx.Rollback()
		} else {
			err = tx.Commit()
		}
	}()

	// Cria o workspace privado
	query := `
	INSERT INTO workspaces (name, description, is_public, owner_uid, created_at)
	VALUES ($1, $2, false, $3, NOW())
	RETURNING id, created_at
	`

	name := ownerUID
	description := "Personal workspace"

	var workspace Workspace
	var createdAt time.Time
	err = tx.QueryRow(
		query,
		name,
		description,
		ownerUID,
	).Scan(&workspace.ID, &createdAt)

	if err != nil {
		return nil, err
	}

	workspace.Name = name
	workspace.Description = description
	workspace.IsPublic = false
	workspace.OwnerUID = ownerUID
	workspace.CreatedAt = createdAt
	workspace.Members = 1

	// Adiciona o dono como admin na tabela user_workspace
	_, err = tx.Exec(`
		INSERT INTO user_workspace (workspace_id, user_id, role, joined_at)
		VALUES ($1, $2, 'admin', NOW())
		`, workspace.ID, ownerUID)

	if err != nil {
		return nil, err
	}

	return &workspace, nil
}

func ListWorkspaceMembers(db *sql.DB, workspaceID int64) ([]WorkspaceMember, error) {
	query := `
		SELECT uw.user_id, u.display_name, u.email, uw.role, uw.joined_at
		FROM user_workspace uw
		JOIN users u ON uw.user_id = u.firebase_uid
		WHERE uw.workspace_id = $1
	`

	rows, err := db.Query(query, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch workspace members: %w", err)
	}
	defer rows.Close()

	var members []WorkspaceMember

	for rows.Next() {
		var member WorkspaceMember
		err := rows.Scan(
			&member.UserID,
			&member.DisplayName,
			&member.Email,
			&member.Role,
			&member.JoinedAt,
		)
		if err != nil {
			return nil, err
		}
		members = append(members, member)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return members, nil
}

func GetWorkspaceInfo(db *sql.DB, workspaceID int64) (*Workspace, error) {
	var workspace Workspace
	query := `
		SELECT id, name, description, is_public, owner_uid, created_at, members
		FROM workspaces
		WHERE id = $1
	`

	err := db.QueryRow(query, workspaceID).Scan(
		&workspace.ID,
		&workspace.Name,
		&workspace.Description,
		&workspace.IsPublic,
		&workspace.OwnerUID,
		&workspace.CreatedAt,
		&workspace.Members,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("workspace not found")
		}
		return nil, err
	}

	return &workspace, nil
}

func UpdateWorkspace(db *sql.DB, workspaceID int64, name string, description string) error {
	// Validações básicas
	if name == "" {
		return errors.New("workspace name cannot be empty")
	}

	// Query de atualização
	_, err := db.Exec(`
		UPDATE workspaces
		SET name = $1, description = $2, updated_at = NOW()
		WHERE id = $3
	`, name, description, workspaceID)

	if err != nil {
		return fmt.Errorf("failed to update workspace: %w", err)
	}

	return nil
}

func DeleteWorkspace(db *sql.DB, workspaceID int64, ownerUID string) error {
	// Verifica se o workspace pertence ao usuário (opcional, mas recomendado para segurança)
	var exists bool
	err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM workspaces
			WHERE id = $1 AND owner_uid = $2
		)
	`, workspaceID, ownerUID).Scan(&exists)

	if err != nil {
		return fmt.Errorf("failed to check workspace ownership: %w", err)
	}

	if !exists {
		return errors.New("workspace not found or user is not the owner")
	}

	// Executa a deleção
	_, err = db.Exec(`
		DELETE FROM workspaces WHERE id = $1
	`, workspaceID)

	if err != nil {
		return fmt.Errorf("failed to delete workspace: %w", err)
	}

	return nil
}

func AddUserToWorkspace(db *sql.DB, workspaceID int64, userID string, role string) error {
	// Validações simples
	if role == "" {
		role = "member"
	}

	// Executa a inserção
	_, err := db.Exec(`
		INSERT INTO user_workspace (workspace_id, user_id, role, joined_at)
		VALUES ($1, $2, $3, NOW())
	`, workspaceID, userID, role)

	// Verifica erro de chave duplicada (usuário já está no workspace)
	if err != nil {
		// Pode melhorar esse tratamento dependendo do driver do banco
		if strings.Contains(err.Error(), "duplicate key") {
			return fmt.Errorf("user %s is already a member of workspace %d", userID, workspaceID)
		}
		return err
	}

	return nil
}

func RemoveUserFromWorkspace(db *sql.DB, workspaceID int64, userID string) error {
	// Executa a deleção
	result, err := db.Exec(`
		DELETE FROM user_workspace
		WHERE workspace_id = $1 AND user_id = $2
	`, workspaceID, userID)

	if err != nil {
		return fmt.Errorf("failed to remove user from workspace: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return errors.New("user not found in workspace")
	}

	return nil
}

func IsWorkspaceMember(db *sql.DB, uid string, workspaceID int64) (bool, error) {
	var exists bool
	err := db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM user_workspace
			WHERE user_id = $1 AND workspace_id = $2
		)
	`, uid, workspaceID).Scan(&exists)

	if err != nil {
		return false, fmt.Errorf("failed to check workspace membership: %w", err)
	}

	return exists, nil
}
