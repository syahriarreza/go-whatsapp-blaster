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

	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo/v4"
	_ "github.com/lib/pq" // Import driver PostgreSQL
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

	db, err := sqlx.Connect("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}

	// Buat database jika belum ada
	dbname := viper.GetString("database.dbname")
	_, err = db.Exec(fmt.Sprintf("CREATE DATABASE \"%s\"", dbname))
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		log.Fatalf("Failed to create database: %v", err)
	}

	// Tutup koneksi awal
	db.Close()

	// Koneksi ke database yang baru dibuat
	connStr = fmt.Sprintf("user=%s password=%s dbname=%s sslmode=%s",
		viper.GetString("database.username"),
		viper.GetString("database.password"),
		dbname,
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

	e.GET("/wa/login/:username", WhatsAppLogin)
	e.POST("/wa/blast/:username", SendBlastMessage)

	log.Fatal(e.Start(":3000"))
}

// HashPassword hashes the given password using bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func RegisterUser(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")

	fmt.Println("Received username:", username)
	fmt.Println("Received password:", password)

	hashedPassword, _ := HashPassword(password)
	fmt.Println("Hashed password:", hashedPassword)

	_, err := db.Exec("INSERT INTO users (username, password) VALUES ($1, $2)", username, hashedPassword)
	if err != nil {
		return c.JSON(http.StatusConflict, echo.Map{"error": "Username already exists"})
	}

	return c.JSON(http.StatusOK, echo.Map{"message": "User registered successfully"})
}

func LoginUser(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")

	var hashedPassword string
	err := db.Get(&hashedPassword, "SELECT password FROM users WHERE username = $1", username)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)) != nil {
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Invalid credentials"})
	}

	return c.JSON(http.StatusOK, echo.Map{"message": "Login successful"})
}

func WhatsAppLogin(c echo.Context) error {
	username := c.Param("username")
	clientLock.Lock()
	defer clientLock.Unlock()

	dbLog := waLog.Stdout("Database", "DEBUG", true)

	// Gunakan PostgreSQL sebagai database untuk menyimpan sesi
	connStr := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=%s",
		viper.GetString("database.username"),
		viper.GetString("database.password"),
		"wa-blaster-session",
		viper.GetString("database.sslmode"))
	container, err := sqlstore.New("postgres", connStr, dbLog)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to create session store"})
	}

	device, _ := container.GetFirstDevice()
	client := whatsmeow.NewClient(device, dbLog)
	clientMap[username] = client

	qrChan, _ := client.GetQRChannel(nil)
	client.Connect()

	for evt := range qrChan {
		if evt.Event == "code" {
			return c.JSON(http.StatusOK, echo.Map{"qr": evt.Code})
		}
	}
	return nil
}

func SendBlastMessage(c echo.Context) error {
	username := c.Param("username")
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
		client.SendMessage(context.TODO(), toJID, &waE2E.Message{
			Conversation: proto.String(message),
		})
	}

	return c.JSON(http.StatusOK, echo.Map{"message": "Messages sent"})
}
