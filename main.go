package main

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo/v4"
	_ "github.com/lib/pq" // Import driver PostgreSQL
	"github.com/sebarcode/codekit"
	"github.com/spf13/viper"
	"github.com/syahriarreza/go-whatsapp-blaster/models"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/protobuf/proto"

	"github.com/doug-martin/goqu/v9"
	_ "github.com/doug-martin/goqu/v9/dialect/postgres" // Import dialect postgres
)

//go:embed templates/*
var templates embed.FS

var db *sqlx.DB
var dbWA *sqlx.DB
var clientMap = make(map[string]*whatsmeow.Client)
var clientLock sync.Mutex
var connStringWA string

var jwtKey = []byte("your_secret_key")

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func init() {
	// Setup Viper untuk membaca konfigurasi
	viper.SetConfigName("app")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}

	var err error

	// Koneksi awal ke PostgreSQL tanpa menentukan nama database
	connStr := fmt.Sprintf("user=%s password=%s sslmode=%s dbname=postgres",
		viper.GetString("database.username"),
		viper.GetString("database.password"),
		viper.GetString("database.sslmode"))

	db, err = sqlx.Connect("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}

	// Buat database app
	_, err = db.Exec(fmt.Sprintf("CREATE DATABASE \"%s\"", viper.GetString("database.dbname")))
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		log.Fatalf("Failed to create database: %v", err)
	}

	// Buat database wa log
	_, err = db.Exec(fmt.Sprintf("CREATE DATABASE \"%s\"", viper.GetString("database.wa_dbname")))
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		log.Fatalf("Failed to create database: %v", err)
	}

	// Tutup koneksi awal
	db.Close()

	// Koneksi ke database yang baru dibuat
	connStr = fmt.Sprintf("user=%s password=%s dbname=%s sslmode=%s",
		viper.GetString("database.username"),
		viper.GetString("database.password"),
		viper.GetString("database.dbname"),
		viper.GetString("database.sslmode"))

	db, err = sqlx.Connect("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %v", err)
	}

	// Buat tabel users jika belum ada
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL
	);
	`
	db.MustExec(schema)

	// db conn for wa
	connStringWA = fmt.Sprintf("user=%s password=%s dbname=%s sslmode=%s",
		viper.GetString("database.username"),
		viper.GetString("database.password"),
		viper.GetString("database.wa_dbname"),
		viper.GetString("database.sslmode"))

	dbWA, err = sqlx.Connect("postgres", connStringWA)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %v", err)
	}
}

func main() {
	// Inisialisasi template engine menggunakan html/template
	tmpl := template.Must(template.New("").ParseFS(templates, "templates/*"))

	e := echo.New()

	e.GET("/", func(c echo.Context) error {
		// Gunakan buffer untuk menulis output template
		var buf strings.Builder
		if err := tmpl.ExecuteTemplate(&buf, "index.html", nil); err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		return c.HTML(http.StatusOK, buf.String())
	})

	e.POST("/register", RegisterUser)
	e.POST("/login", LoginUser)

	e.GET("/wa/login", WhatsAppLogin, jwtMiddleware)
	e.POST("/wa/logout", WhatsAppLogout, jwtMiddleware)
	e.GET("/wa/check", CheckWhatsAppID, jwtMiddleware)
	e.POST("/wa/blast/:username", SendBlastMessage, jwtMiddleware)

	// Tambahkan defer untuk memanggil exitHandler ketika aplikasi mati
	defer exitHandler()

	log.Fatal(e.Start(":3000"))
}

// HashPassword hashes the given password using bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// RegisterUser handles user registration
func RegisterUser(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	hashedPassword, _ := HashPassword(password)

	// TODO: check username tidak boleh sama

	sql, args, err := goqu.Insert("users").
		Rows(
			models.User{Username: username, Password: hashedPassword},
		).
		ToSQL()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to build SQL query"})
	}

	_, err = db.Exec(sql, args...)
	if err != nil {
		return c.JSON(http.StatusConflict, echo.Map{"error": "Username already exists"})
	}

	return c.JSON(http.StatusOK, echo.Map{"message": "User registered successfully"})
}

// LoginUser handles user login and generates a JWT token
func LoginUser(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")

	var hashedPassword string
	sql, args, err := goqu.From("users").
		Select("password").
		Where(goqu.Ex{"username": username}).
		ToSQL()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to build SQL query"})
	}

	err = db.Get(&hashedPassword, sql, args...)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)) != nil {
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Invalid credentials"})
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Could not generate token"})
	}

	return c.JSON(http.StatusOK, echo.Map{"token": tokenString})
}

// WhatsAppLogin handles the WhatsApp login process for a given username
func WhatsAppLogin(c echo.Context) error {
	clientLock.Lock()
	defer clientLock.Unlock()

	// Ambil username dari context
	username := c.Get("username").(string)

	// Check if client already exists
	if cli, exists := clientMap[username]; exists && cli != nil {
		return c.JSON(http.StatusConflict, echo.Map{"error": "No Need to Login, Client already exists"})
	}

	// Get whatsapp_id from users table based on username
	var whatsappID string
	sql, args, err := goqu.From("users").
		Select("whatsapp_id").
		Where(goqu.Ex{"username": username}).
		ToSQL()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to build SQL query"})
	}

	db.Get(&whatsappID, sql, args...)

	if whatsappID != "" {
		// check DB and clear if data exists, supaya tidak error
		waTables, err := getAllTables(dbWA)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to get all tables"})
		}

		for _, watbl := range waTables {
			sql, args, err := goqu.Delete(watbl).Where(goqu.Or(goqu.Ex{"jid": whatsappID}, goqu.Ex{"our_jid": whatsappID})).ToSQL()
			if err != nil {
				return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to build SQL query for clearing data"})
			}

			db.Exec(sql, args...)
		}
	}

	dbLog := waLog.Stdout("Database", "DEBUG", true)
	container, err := sqlstore.New("postgres", connStringWA, dbLog)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to create session store"})
	}

	device, err := container.GetFirstDevice()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to get device"})
	}

	client := whatsmeow.NewClient(device, dbLog)
	clientMap[username] = client

	qrChan, _ := client.GetQRChannel(context.Background())
	client.Connect()

	// Save client.Store.ID to users.whatsapp_id
	sql, args, err = goqu.Update("users").
		Set(goqu.Record{"whatsapp_id": client.Store.ID}).
		Where(goqu.Ex{"username": username}).
		ToSQL()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to build SQL query"})
	}

	_, err = db.Exec(sql, args...)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to update WhatsApp ID"})
	}

	for evt := range qrChan {
		if evt.Event == "code" {
			code := evt.Code
			// qrterminal.GenerateHalfBlock(code, qrterminal.L, os.Stdout) // display on terminal
			return c.JSON(http.StatusOK, echo.Map{"qr": code})
		}
	}

	return nil
}

func CheckWhatsAppID(c echo.Context) error {
	username := c.Get("username").(string)

	client, exists := clientMap[username]
	if !exists {
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "WhatsApp not logged in"})
	}

	return c.JSON(http.StatusOK, echo.Map{"whatsapp_id": client.Store.ID})
}

// SendBlastMessage sends a message to multiple WhatsApp numbers
func SendBlastMessage(c echo.Context) error {
	username := c.Get("username").(string)

	clientLock.Lock()
	client, exists := clientMap[username]
	clientLock.Unlock()

	if !exists {
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "WhatsApp not logged in"})
	}

	numbers := strings.Split(c.FormValue("numbers"), ",")
	message := c.FormValue("message")

	for _, number := range numbers {
		toJID, e := types.ParseJID(number)
		if e != nil {
			return c.JSON(http.StatusUnauthorized, echo.Map{"error": e.Error()})
		}
		resp, e := client.SendMessage(context.TODO(), toJID, &waE2E.Message{
			Conversation: proto.String(message),
		})
		if e != nil {
			return c.JSON(http.StatusInternalServerError, echo.Map{"error": e.Error()})
		}
		fmt.Println("WA SengMessage:", codekit.JsonStringIndent(resp, "\t"))
	}

	return c.JSON(http.StatusOK, echo.Map{"message": "Messages sent"})
}

func WhatsAppLogout(c echo.Context) error {
	username := c.Get("username").(string)

	clientLock.Lock()
	defer clientLock.Unlock()

	client, exists := clientMap[username]
	if !exists {
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "WhatsApp not logged in"})
	}

	client.Disconnect()
	delete(clientMap, username)

	// TODO: clear DB data based on JID

	return c.JSON(http.StatusOK, echo.Map{"message": "Logged out successfully"})
}

func jwtMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		authHeader := c.Request().Header.Get("Authorization")
		if authHeader == "" {
			return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Missing token"})
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Invalid token"})
		}

		// Set username in context
		c.Set("username", claims.Username)

		return next(c)
	}
}

func getAllTables(db *sqlx.DB) ([]string, error) {
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

func exitHandler() {
	tables, err := getAllTables(dbWA)
	if err != nil {
		log.Printf("Error getting tables: %v", err)
		return
	}

	for _, table := range tables {
		_, err := dbWA.Exec(fmt.Sprintf("DELETE FROM %s", table))
		if err != nil {
			log.Printf("Error clearing table %s: %v", table, err)
		}
	}
}
