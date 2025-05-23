package models

import (
	"database/sql"
	"errors"
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

func CreatePrivateWorkspace(db *sql.DB, ownerUID string) (*Workspace, error) {
	// Verifica se já existe um workspace privado para esse usuário
	var existingID int64
	err := db.QueryRow(`
		SELECT id FROM workspaces WHERE owner_uid = $1 AND is_public = false
	`, ownerUID).Scan(&existingID)

	if err != nil && err != sql.ErrNoRows {
		return nil, err // erro de banco
	}

	if err == nil {
		// Já existe um workspace privado
		return nil, errors.New("private workspace already exists")
	}

	// Se não existir, cria um
	query := `
		INSERT INTO workspaces (name, description, is_public, owner_uid, created_at)
		VALUES ($1, $2, false, $3, NOW())
		RETURNING id, created_at
	`

	name := ownerUID
	description := "Personal workspace"

	var workspace Workspace
	err = db.QueryRow(
		query,
		name,
		description,
		ownerUID,
	).Scan(&workspace.ID, &workspace.CreatedAt)

	if err != nil {
		return nil, err
	}

	workspace.Name = name
	workspace.Description = description
	workspace.IsPublic = false
	workspace.OwnerUID = ownerUID

	return &workspace, nil
}
