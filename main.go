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
	"github.com/syahriarreza/go-whatsapp-blaster/helper"
	"github.com/syahriarreza/go-whatsapp-blaster/middleware"
	"github.com/syahriarreza/go-whatsapp-blaster/models"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
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

	e.GET("/wa/login", WhatsAppLogin, middleware.JwtMiddleware)
	e.POST("/wa/logout", WhatsAppLogout, middleware.JwtMiddleware)
	e.GET("/wa/check", CheckWhatsAppID, middleware.JwtMiddleware)
	e.POST("/wa/blast/:username", SendBlastMessage, middleware.JwtMiddleware)

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
	claims := &middleware.Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(middleware.JwtKey)
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

	whatsappID, err := helper.GetWhatsappID(db, username)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to get WhatsApp ID"})
	}

	if whatsappID != "" {
		// check DB and clear if data exists, supaya tidak error
		if err := helper.ClearWAData(dbWA, whatsappID); err != nil {
			return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to clear WhatsApp data"})
		}

		// TODO: clear whatsapp_id in users table
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

	client.AddEventHandler(func(evt interface{}) {
		fmt.Printf("\n\n Received an event! %+v\n\n", evt)
		switch v := evt.(type) {
		case *events.Message:
			fmt.Printf("\n\n Message: %+v\nv.Info.Chat:%s\n\n", v.Message, codekit.JsonStringIndent(v.Info.Chat, "\t"))
			if *v.Message.ExtendedTextMessage.Text == "ping" {
				client.SendMessage(context.Background(), v.Info.Chat, &waE2E.Message{
					Conversation: proto.String("pong"),
				})
			}
		// case *events.Receipt:
		// 	fmt.Printf("\n\n Received a Receipt! %+v\n\n", v)
		case *events.ConnectFailure:
			fmt.Printf("\n\n Received a ConnectFailure! %+v\n\n", v)
		case *events.Disconnected:
			fmt.Printf("\n\n Received a Disconnected! %+v\n\n", v)
		case *events.Picture:
			fmt.Printf("\n\n Received a Picture! %+v\n\n", v)
		case *events.Presence:
			fmt.Printf("\n\n Received a Presence! %+v\n\n", v)
		}
	})

	qrChan, _ := client.GetQRChannel(context.Background())

	fmt.Println("WA connecting...")
	client.Connect()
	fmt.Println("WA Connected!")

	// Save client.Store.ID to users.whatsapp_id // TODO: not updating
	sql, args, err := goqu.Update("users").
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

	fmt.Println("WA Start Looping QR Channel. . .")
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

	fmt.Printf("\n\nClient ID: %s\n", codekit.JsonStringIndent(client.Store.ID, "\t"))

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
		toJID := types.NewJID(number, types.DefaultUserServer)
		// toJID, e := types.ParseJID(fmt.Sprintf("%s@%s", number, types.DefaultUserServer))
		// if e != nil {
		// 	return c.JSON(http.StatusUnauthorized, echo.Map{"error": e.Error()})
		// }
		fmt.Println("toJID:", toJID)

		resp, e := client.SendMessage(context.TODO(), toJID, &waE2E.Message{
			Conversation: proto.String(message),
		})
		if e != nil {
			return c.JSON(http.StatusInternalServerError, echo.Map{"error": e.Error()})
		}
		fmt.Println("WA SendMessage:", codekit.JsonStringIndent(resp, "\t"))
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

	whatsappID, err := helper.GetWhatsappID(db, username)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to get WhatsApp ID"})
	}

	if err := helper.ClearWAData(dbWA, whatsappID); err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to clear WhatsApp data"})
	}

	return c.JSON(http.StatusOK, echo.Map{"message": "Logged out successfully"})
}

func exitHandler() {
	helper.ClearWAData(dbWA)
}
