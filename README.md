# WhatsApp Blaster

## Introduction
WhatsApp Blaster is a multi-tenant WhatsApp message broadcasting system built using Golang and WhatsMeow library. It allows users to log in with their WhatsApp accounts, register multiple recipients, and send bulk messages.

## Features
- User registration and authentication with JWT
- Secure password hashing using bcrypt
- WhatsApp login via QR code scanning
- Bulk messaging to multiple WhatsApp numbers
- Secure multi-tenant architecture for multiple users
- API endpoints for seamless integration
- Embedded HTML UI for user interaction

## Technologies Used
- **Backend**: Golang (Echo framework)
- **Database**: PostgreSQL (SQLX, Goqu ORM)
- **Authentication**: JWT
- **WhatsApp API**: WhatsMeow
- **Frontend**: Embedded HTML

## Installation

### 1. Clone the repository
```sh
git clone https://github.com/your-repo/go-whatsapp-blaster.git
cd go-whatsapp-blaster
```

### 2. Configure the application
Create a configuration file `app.yml` in the root directory with the following structure:

```yaml
database:
  username: "your_db_username"
  password: "your_db_password"
  dbname: "whatsapp_blaster"
  wa_dbname: "whatsapp_blaster_wa"
  sslmode: "disable"
```

### 3. Install dependencies
```sh
go mod tidy
```

### 4. Run the application
```sh
go run main.go
```

### 5. Access the UI
Open your browser and go to:
```
http://localhost:3000
```

## API Endpoints

### Authentication
- `POST /register` - Register a new user
- `POST /login` - Login and receive JWT token

### WhatsApp Operations
- `GET /wa/login` - Generate QR Code for WhatsApp login
- `GET /wa/check` - Check WhatsApp login status
- `POST /wa/blast/:username` - Send bulk messages
- `POST /wa/logout` - Logout from WhatsApp

## License
MIT License.
