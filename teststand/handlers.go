package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
	"time"
)

type handlers struct {
	db      *sql.DB
	tmplDir string
}

func newHandlers(db *sql.DB, tmplDir string) *handlers {
	return &handlers{db: db, tmplDir: tmplDir}
}

// ---- index ----

func (h *handlers) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	h.render(w, "index.html", nil)
}

// ---- search (SQL Injection — INTENTIONALLY VULNERABLE) ----

type searchData struct {
	Query   string
	Results []product
	Err     string
}

type product struct {
	ID          int
	Name        string
	Description string
	Price       float64
}

func (h *handlers) search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	data := searchData{Query: q}

	if q != "" {
		// INTENTIONALLY VULNERABLE: direct string concatenation — DO NOT fix
		sqlQuery := fmt.Sprintf("SELECT id, name, description, price FROM products WHERE name ILIKE '%%%s%%'", q)
		rows, err := h.db.QueryContext(r.Context(), sqlQuery)
		if err != nil {
			data.Err = err.Error()
		} else {
			defer rows.Close()
			for rows.Next() {
				var p product
				if scanErr := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Price); scanErr != nil {
					data.Err = scanErr.Error()
					break
				}
				data.Results = append(data.Results, p)
			}
		}
	}

	h.render(w, "search.html", data)
}

// ---- login (SQL Injection auth bypass — INTENTIONALLY VULNERABLE) ----

type loginData struct {
	Message string
}

func (h *handlers) login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		h.render(w, "login.html", loginData{})
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	// INTENTIONALLY VULNERABLE: direct string concatenation — DO NOT fix
	sqlQuery := fmt.Sprintf("SELECT username, role FROM users WHERE username='%s' AND password='%s'", username, password)
	row := h.db.QueryRowContext(r.Context(), sqlQuery)

	var uname, role string
	err := row.Scan(&uname, &role)
	if err != nil {
		h.render(w, "login.html", loginData{Message: "Неверные учётные данные"})
		return
	}

	h.render(w, "login.html", loginData{Message: fmt.Sprintf("Добро пожаловать, %s! Роль: %s", uname, role)})
}

// ---- profile (Reflected XSS — INTENTIONALLY VULNERABLE) ----

type profileData struct {
	Name template.HTML // INTENTIONALLY unescaped — DO NOT fix
}

func (h *handlers) profile(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// INTENTIONALLY VULNERABLE: template.HTML bypasses auto-escaping — DO NOT fix
	h.render(w, "profile.html", profileData{Name: template.HTML(name)})
}

// ---- guestbook (Stored XSS — INTENTIONALLY VULNERABLE) ----

type guestbookEntry struct {
	ID        int
	Author    string
	Message   template.HTML // INTENTIONALLY unescaped — DO NOT fix
	CreatedAt time.Time
}

type guestbookData struct {
	Entries []guestbookEntry
}

func (h *handlers) guestbook(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		author := r.FormValue("author")
		message := r.FormValue("message")
		// INTENTIONALLY VULNERABLE: no sanitization — DO NOT fix
		_, err := h.db.ExecContext(r.Context(),
			"INSERT INTO guestbook (author, message) VALUES ($1, $2)",
			author, message,
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/guestbook", http.StatusSeeOther)
		return
	}

	rows, err := h.db.QueryContext(r.Context(),
		"SELECT id, author, message, created_at FROM guestbook ORDER BY created_at DESC",
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var entries []guestbookEntry
	for rows.Next() {
		var e guestbookEntry
		var msg string
		if scanErr := rows.Scan(&e.ID, &e.Author, &msg, &e.CreatedAt); scanErr != nil {
			http.Error(w, scanErr.Error(), http.StatusInternalServerError)
			return
		}
		// INTENTIONALLY VULNERABLE: template.HTML bypasses auto-escaping — DO NOT fix
		e.Message = template.HTML(msg)
		entries = append(entries, e)
	}

	h.render(w, "guestbook.html", guestbookData{Entries: entries})
}

// ---- helper ----
// Each render call parses layout + the specific page file together so that
// each page can define its own "content" block without name collisions.

func (h *handlers) render(w http.ResponseWriter, page string, data any) {
	layoutFile := filepath.Join(h.tmplDir, "layout.html")
	pageFile := filepath.Join(h.tmplDir, page)

	tmpl, err := template.ParseFiles(layoutFile, pageFile)
	if err != nil {
		http.Error(w, "template parse error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, "template execute error: "+err.Error(), http.StatusInternalServerError)
	}
}
