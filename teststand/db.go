package main

import (
	"database/sql"
	"log"

	_ "github.com/lib/pq"
)

func initDB(dsn string) *sql.DB {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("initDB: open: %v", err)
	}
	if err := db.Ping(); err != nil {
		log.Fatalf("initDB: ping: %v", err)
	}
	log.Println("database connection established")
	return db
}

func migrate(db *sql.DB) {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id       SERIAL PRIMARY KEY,
			username VARCHAR(100) NOT NULL UNIQUE,
			password VARCHAR(100) NOT NULL,
			role     VARCHAR(50) DEFAULT 'user'
		)`,
		`CREATE TABLE IF NOT EXISTS products (
			id          SERIAL PRIMARY KEY,
			name        VARCHAR(200) NOT NULL,
			description TEXT,
			price       NUMERIC(10,2)
		)`,
		`CREATE TABLE IF NOT EXISTS guestbook (
			id         SERIAL PRIMARY KEY,
			author     VARCHAR(100) NOT NULL,
			message    TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW()
		)`,
	}

	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			log.Fatalf("migrate: %v", err)
		}
	}
	log.Println("migrations applied")
}

func seed(db *sql.DB) {
	// Users
	users := []struct {
		username, password, role string
	}{
		{"admin", "admin123", "admin"},
		{"user", "password", "user"},
		{"analyst", "analyst1", "analyst"},
	}
	for _, u := range users {
		_, err := db.Exec(
			`INSERT INTO users (username, password, role) VALUES ($1, $2, $3) ON CONFLICT (username) DO NOTHING`,
			u.username, u.password, u.role,
		)
		if err != nil {
			log.Fatalf("seed users: %v", err)
		}
	}

	// Products (Russian names)
	products := []struct {
		name, description string
		price             float64
	}{
		{"Ноутбук Lenovo IdeaPad", "15.6 дюймов, Intel Core i5, 8 ГБ ОЗУ", 54990.00},
		{"Смартфон Samsung Galaxy A54", "6.4 дюймов, 128 ГБ, 5G", 29999.00},
		{"Наушники Sony WH-1000XM5", "Беспроводные, шумоподавление", 22500.00},
		{"Монитор LG 27 IPS", "4K UHD, 60 Гц, HDMI", 38000.00},
		{"Клавиатура Logitech MX Keys", "Беспроводная, механическая", 8990.00},
		{"Веб-камера Logitech C920", "Full HD 1080p, встроенный микрофон", 5490.00},
	}
	for _, p := range products {
		_, err := db.Exec(
			`INSERT INTO products (name, description, price) VALUES ($1, $2, $3)
			 ON CONFLICT DO NOTHING`,
			p.name, p.description, p.price,
		)
		if err != nil {
			log.Fatalf("seed products: %v", err)
		}
	}

	// Guestbook
	entries := []struct {
		author, message string
	}{
		{"Иван Петров", "Отличный сайт, нашёл всё что нужно!"},
		{"Мария Сидорова", "Быстрая доставка и хорошие цены."},
		{"Алексей К.", "Спасибо за подробные описания товаров."},
	}
	for _, e := range entries {
		_, err := db.Exec(
			`INSERT INTO guestbook (author, message) VALUES ($1, $2)`,
			e.author, e.message,
		)
		if err != nil {
			log.Fatalf("seed guestbook: %v", err)
		}
	}

	log.Println("seed data inserted")
}
