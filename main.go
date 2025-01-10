package main

import (
	"embed"
	"html/template"
	"log"
	"net/http"
	"strings"
	"sync"

	"context"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
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
	// Setup SQLite Database
	var err error
	db, err = sqlx.Connect("sqlite3", "multi_tenant.db")
	if err != nil {
		log.Fatalf("Failed to connect to DB: %v", err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL
	);
	`
	db.MustExec(schema)
}

func main() {
	r := gin.Default()

	tmpl := template.Must(template.New("").ParseFS(templates, "templates/*"))
	r.GET("/", func(c *gin.Context) {
		tmpl.ExecuteTemplate(c.Writer, "index.html", nil)
	})

	r.POST("/register", RegisterUser)
	r.POST("/login", LoginUser)

	r.GET("/wa/login/:username", WhatsAppLogin)
	r.POST("/wa/blast/:username", SendBlastMessage)

	r.Run(":3000")
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func RegisterUser(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	hashedPassword, _ := HashPassword(password)
	_, err := db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, hashedPassword)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User registered successfully"})
}

func LoginUser(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	var hashedPassword string
	err := db.Get(&hashedPassword, "SELECT password FROM users WHERE username = ?", username)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
}

func WhatsAppLogin(c *gin.Context) {
	username := c.Param("username")
	clientLock.Lock()
	defer clientLock.Unlock()

	dbLog := waLog.Stdout("Database", "DEBUG", true)
	container, err := sqlstore.New("sqlite", "file:"+username+"_session.db?_foreign_keys=on", dbLog)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session store"})
		return
	}

	device, _ := container.GetFirstDevice()
	client := whatsmeow.NewClient(device, dbLog)
	clientMap[username] = client

	qrChan, _ := client.GetQRChannel(nil)
	client.Connect()

	for evt := range qrChan {
		if evt.Event == "code" {
			c.JSON(http.StatusOK, gin.H{"qr": evt.Code})
			return
		}
	}
}

func SendBlastMessage(c *gin.Context) {
	username := c.Param("username")
	clientLock.Lock()
	client, exists := clientMap[username]
	clientLock.Unlock()

	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "WhatsApp not logged in"})
		return
	}

	numbers := strings.Split(c.PostForm("numbers"), ",")
	message := c.PostForm("message")

	for _, number := range numbers {
		toJID, e := types.ParseJID(number)
		if e != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": e.Error()})
			return
		}
		// client.SendMessage(context.TODO(), types.BroadcastServerJID, number+"@s.whatsapp.net", message)
		client.SendMessage(context.TODO(), toJID, &waE2E.Message{
			Conversation: proto.String(message),
		})
	}

	c.JSON(http.StatusOK, gin.H{"message": "Messages sent"})
}
