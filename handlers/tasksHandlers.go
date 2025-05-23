package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// createTaskHandler cria uma nova tarefa em um workspace
func createTaskHandler(w http.ResponseWriter, r *http.Request) {
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

	var task struct {
		Title      string    `json:"title"`
		Content    string    `json:"content"`
		Priority   string    `json:"priority"`
		Status     string    `json:"status"`
		Expiration time.Time `json:"expiration"`
	}

	if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validar prioridade
	validPriorities := map[string]bool{"low": true, "medium": true, "high": true}
	if !validPriorities[task.Priority] {
		http.Error(w, "Prioridade inválida", http.StatusBadRequest)
		return
	}

	// Validar status
	validStatuses := map[string]bool{"pending": true, "in_progress": true, "completed": true}
	if task.Status != "" && !validStatuses[task.Status] {
		http.Error(w, "Status inválido", http.StatusBadRequest)
		return
	}

	// Obter ID do usuário
	var userID int
	err = db.QueryRow("SELECT id FROM users WHERE firebase_uid = $1", uid).Scan(&userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Inserir nova tarefa
	query := `INSERT INTO tarefas (title, conteudo, prioridade, status, expiracao, criado_por, workspace_id)
              VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`
	var id int
	err = db.QueryRow(query,
		task.Title,
		task.Content,
		task.Priority,
		task.Status,
		task.Expiration,
		userID,
		workspaceID,
	).Scan(&id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]int{"id": id}
	json.NewEncoder(w).Encode(response)
}

// getTasksHandler lista todas as tarefas de um workspace
func getTasksHandler(w http.ResponseWriter, r *http.Request) {
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

	// Obter parâmetros de query para filtragem
	queryParams := r.URL.Query()
	statusFilter := queryParams.Get("status")
	priorityFilter := queryParams.Get("priority")

	// Construir query base
	query := `
        SELECT t.id, t.title, t.conteudo, t.prioridade, t.status, t.expiracao, 
               t.criado_por, t.workspace_id, t.created_at, u.username
        FROM tarefas t
        JOIN users u ON t.criado_por = u.id
        WHERE t.workspace_id = $1
    `
	params := []interface{}{workspaceID}
	paramCount := 2

	// Adicionar filtros
	if statusFilter != "" {
		query += fmt.Sprintf(" AND t.status = $%d", paramCount)
		params = append(params, statusFilter)
		paramCount++
	}

	if priorityFilter != "" {
		query += fmt.Sprintf(" AND t.prioridade = $%d", paramCount)
		params = append(params, priorityFilter)
		paramCount++
	}

	query += " ORDER BY t.created_at DESC"

	rows, err := db.Query(query, params...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	tasks := []map[string]interface{}{}
	for rows.Next() {
		var task Task
		var createdByUsername string
		var expiration sql.NullTime

		err := rows.Scan(
			&task.ID, &task.Title, &task.Content, &task.Priority, &task.Status,
			&expiration, &task.CreatedBy, &task.WorkspaceID, &task.CreatedAt,
			&createdByUsername,
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		taskMap := map[string]interface{}{
			"id":           task.ID,
			"title":        task.Title,
			"content":      task.Content,
			"priority":     task.Priority,
			"status":       task.Status,
			"created_by":   createdByUsername,
			"workspace_id": task.WorkspaceID,
			"created_at":   task.CreatedAt,
		}

		if expiration.Valid {
			taskMap["expiration"] = expiration.Time
		}

		tasks = append(tasks, taskMap)
	}

	json.NewEncoder(w).Encode(tasks)
}

// updateTaskHandler atualiza uma tarefa existente
func updateTaskHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	taskID := vars["id"]

	// Obter UID do usuário a partir do token Firebase
	uid, err := getUIDFromToken(r)
	if err != nil {
		http.Error(w, "Não autorizado", http.StatusUnauthorized)
		return
	}

	// Verificar se o usuário é o criador da tarefa ou membro admin do workspace
	canEdit, err := canEditTask(uid, taskID)
	if err != nil || !canEdit {
		http.Error(w, "Sem permissão para editar esta tarefa", http.StatusForbidden)
		return
	}

	var updates struct {
		Title      *string    `json:"title"`
		Content    *string    `json:"content"`
		Priority   *string    `json:"priority"`
		Status     *string    `json:"status"`
		Expiration *time.Time `json:"expiration"`
	}

	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Construir query dinâmica
	query := "UPDATE tarefas SET "
	params := []interface{}{}
	paramCount := 1

	if updates.Title != nil {
		query += fmt.Sprintf("title = $%d, ", paramCount)
		params = append(params, *updates.Title)
		paramCount++
	}

	if updates.Content != nil {
		query += fmt.Sprintf("conteudo = $%d, ", paramCount)
		params = append(params, *updates.Content)
		paramCount++
	}

	if updates.Priority != nil {
		// Validar prioridade
		validPriorities := map[string]bool{"low": true, "medium": true, "high": true}
		if !validPriorities[*updates.Priority] {
			http.Error(w, "Prioridade inválida", http.StatusBadRequest)
			return
		}
		query += fmt.Sprintf("prioridade = $%d, ", paramCount)
		params = append(params, *updates.Priority)
		paramCount++
	}

	if updates.Status != nil {
		// Validar status
		validStatuses := map[string]bool{"pending": true, "in_progress": true, "completed": true}
		if !validStatuses[*updates.Status] {
			http.Error(w, "Status inválido", http.StatusBadRequest)
			return
		}
		query += fmt.Sprintf("status = $%d, ", paramCount)
		params = append(params, *updates.Status)
		paramCount++
	}

	if updates.Expiration != nil {
		query += fmt.Sprintf("expiracao = $%d, ", paramCount)
		params = append(params, *updates.Expiration)
		paramCount++
	}

	// Remover a vírgula final e adicionar a cláusula WHERE
	query = strings.TrimSuffix(query, ", ") + " WHERE id = $" + strconv.Itoa(paramCount)
	params = append(params, taskID)

	_, err = db.Exec(query, params...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// deleteTaskHandler remove uma tarefa
func deleteTaskHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	taskID := vars["id"]

	// Obter UID do usuário a partir do token Firebase
	uid, err := getUIDFromToken(r)
	if err != nil {
		http.Error(w, "Não autorizado", http.StatusUnauthorized)
		return
	}

	// Verificar se o usuário é o criador da tarefa ou admin do workspace
	canDelete, err := canDeleteTask(uid, taskID)
	if err != nil || !canDelete {
		http.Error(w, "Sem permissão para deletar esta tarefa", http.StatusForbidden)
		return
	}

	_, err = db.Exec("DELETE FROM tarefas WHERE id = $1", taskID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Funções auxiliares para tarefas
func canEditTask(uid string, taskID string) (bool, error) {
	var userID int
	err := db.QueryRow("SELECT id FROM users WHERE firebase_uid = $1", uid).Scan(&userID)
	if err != nil {
		return false, err
	}

	// Verificar se é o criador da tarefa
	var isCreator bool
	err = db.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM tarefas WHERE id = $1 AND criado_por = $2)",
		taskID, userID,
	).Scan(&isCreator)
	if err != nil {
		return false, err
	}
	if isCreator {
		return true, nil
	}

	// Verificar se é admin do workspace da tarefa
	var isAdmin bool
	err = db.QueryRow(`
        SELECT EXISTS(
            SELECT 1 FROM membros_workspace mw
            JOIN tarefas t ON mw.workspace_id = t.workspace_id
            WHERE t.id = $1 AND mw.usuario_id = $2 AND mw.role = 'admin'
        )`, taskID, userID,
	).Scan(&isAdmin)
	return isAdmin, err
}

func canDeleteTask(uid string, taskID string) (bool, error) {
	// Mesma lógica que canEditTask para este exemplo
	return canEditTask(uid, taskID)
}
