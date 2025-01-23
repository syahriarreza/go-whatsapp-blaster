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
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/protobuf/proto"
)

//go:embed templates/*
var templates embed.FS

var db *sqlx.DB
var clientMap = make(map[string]*whatsmeow.Client)
var clientLock sync.Mutex

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

	// Koneksi awal ke PostgreSQL tanpa menentukan nama database
	connStr := fmt.Sprintf("user=%s password=%s sslmode=%s dbname=postgres",
		viper.GetString("database.username"),
		viper.GetString("database.password"),
		viper.GetString("database.sslmode"))

	var err error // Tambahkan ini di luar fungsi init jika diperlukan

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

	// Pasang middleware jwtMiddleware pada rute yang memerlukan autentikasi
	e.GET("/wa/login", WhatsAppLogin, jwtMiddleware)
	e.POST("/wa/blast/:username", SendBlastMessage, jwtMiddleware)

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

	_, err := db.Exec("INSERT INTO users (username, password) VALUES ($1, $2)", username, hashedPassword)
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
	err := db.Get(&hashedPassword, "SELECT password FROM users WHERE username = $1", username)
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

	dbLog := waLog.Stdout("Database", "DEBUG", true)

	connStr := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=%s",
		viper.GetString("database.username"),
		viper.GetString("database.password"),
		viper.GetString("database.wa_dbname"),
		viper.GetString("database.sslmode"))
	container, err := sqlstore.New("postgres", connStr, dbLog)
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

	for evt := range qrChan {
		if evt.Event == "code" {
			code := evt.Code
			// qrterminal.GenerateHalfBlock(code, qrterminal.L, os.Stdout) // display on terminal
			return c.JSON(http.StatusOK, echo.Map{"qr": code})
		}
	}

	return nil
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
