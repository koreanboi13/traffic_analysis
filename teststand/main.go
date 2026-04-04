package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://teststand:teststand@localhost:5432/teststand?sslmode=disable"
	}

	db := initDB(dsn)
	defer db.Close()

	migrate(db)
	seed(db)

	// Resolve templates directory relative to the binary / source file.
	tmplDir := os.Getenv("TEMPLATES_DIR")
	if tmplDir == "" {
		// When running via `go run` or a binary placed next to the source tree,
		// resolve relative to this source file's directory.
		_, srcFile, _, ok := runtime.Caller(0)
		if ok {
			tmplDir = filepath.Join(filepath.Dir(srcFile), "templates")
		} else {
			tmplDir = "templates"
		}
	}

	h := newHandlers(db, tmplDir)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8888"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", h.index)
	mux.HandleFunc("/search", h.search)
	mux.HandleFunc("/login", h.login)
	mux.HandleFunc("/profile", h.profile)
	mux.HandleFunc("/guestbook", h.guestbook)

	addr := ":" + port
	log.Printf("server listening on %s (templates: %s)", addr, tmplDir)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("ListenAndServe: %v", err)
	}
}
