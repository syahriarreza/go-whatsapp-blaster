package models

type User struct {
	ID         int    `db:"id"`
	Username   string `db:"username"`
	Password   string `db:"password"`
	WhatsappID string `db:"whatsapp_id"`
}
