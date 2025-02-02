package helper

import (
	"fmt"
	"log"

	"github.com/doug-martin/goqu/v9"
	"github.com/jmoiron/sqlx"
)

func GetWhatsappID(db *sqlx.DB, username string) (string, error) {
	var whatsappID string
	sql, _, err := goqu.From("users").
		Select("whatsapp_id").
		Where(goqu.Ex{"username": username}).
		ToSQL()
	if err != nil {
		return "", err
	}

	err = db.Get(&whatsappID, sql)
	if err != nil {
		return "", err
	}
	return whatsappID, nil
}

func GetAllTables(db *sqlx.DB) ([]string, error) {
	var tables []string

	dialect := goqu.Dialect("postgres") // Change dialect if needed
	query, _, err := dialect.Select("table_name").
		From("information_schema.tables").
		Where(goqu.Ex{"table_schema": "public"}). // Adjust schema if necessary
		ToSQL()
	if err != nil {
		return nil, err
	}

	err = db.Select(&tables, query)
	if err != nil {
		return nil, err
	}

	return tables, nil
}

func ClearWAData(dbWA *sqlx.DB, username ...string) error {
	tables, err := GetAllTables(dbWA)
	if err != nil {
		log.Printf("Error getting tables: %v", err)
		return err
	}

	for _, table := range tables {
		if len(username) > 0 && username[0] != "" {
			// Clear only the tables related to the username
			whatsappID, err := GetWhatsappID(dbWA, username[0])
			if err != nil {
				log.Printf("Error getting WhatsApp ID for username %s: %v", username[0], err)
				return err
			}

			sql, args, err := goqu.Delete(table).Where(goqu.Or(goqu.Ex{"jid": whatsappID}, goqu.Ex{"our_jid": whatsappID})).ToSQL()
			if err != nil {
				return err
			}

			dbWA.Exec(sql, args...)
		} else {
			// Clear all tables
			_, err := dbWA.Exec(fmt.Sprintf("DELETE FROM %s", table))
			if err != nil {
				log.Printf("Error clearing table %s: %v", table, err)
				return err
			}
		}
	}

	return nil
}
