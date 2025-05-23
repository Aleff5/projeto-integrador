package database

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

func ConnectPostgres() (*sql.DB, error) {
	connStr := "host=localhost port=5432 user=postgres password=suasenha dbname=seubanco sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		return nil, err
	}

	fmt.Println("Conectado ao PostgreSQL!")
	return db, nil
}
