package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/koreanboi13/traffic_analysis/waf/config"
	"github.com/koreanboi13/traffic_analysis/waf/internal/api/middleware"
	"github.com/koreanboi13/traffic_analysis/waf/internal/postgres"
	"github.com/koreanboi13/traffic_analysis/waf/internal/rules"
	"github.com/rs/cors"
	"go.uber.org/zap"
)

// Server holds the Admin API router and configuration.
type Server struct {
	Router chi.Router
	cfg    config.Config
}

// NewServer creates a new Admin API server with all routes, CORS, JWT, and RBAC middleware.
// Public route: POST /api/auth/login
// Authenticated routes (Analyst + Admin): GET /api/rules, GET /api/rules/{id}
// Admin-only routes: POST /api/rules, PUT /api/rules/{id}, DELETE /api/rules/{id}
func NewServer(cfg config.Config, db *postgres.DB, engine *rules.RuleEngine, logger *zap.Logger) *Server {
	r := chi.NewRouter()

	// Standard chi middleware
	r.Use(chimw.RequestID)
	r.Use(chimw.Recoverer)

	// CORS for React panel (panel may run on a different origin)
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	})
	r.Use(c.Handler)

	secret := []byte(cfg.Auth.JWTSecret)

	// Public route: login (no JWT required)
	r.Post("/api/auth/login", HandleLogin(db, secret, cfg.Auth.TokenTTL, logger))

	// Health check
	r.Get("/api/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Authenticated routes
	r.Group(func(r chi.Router) {
		r.Use(middleware.JWTMiddleware(secret))

		// Analyst + Admin: read rules
		r.Get("/api/rules", HandleListRules(db, logger))
		r.Get("/api/rules/{id}", HandleGetRule(db, logger))

		// Admin only: mutate rules
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireRole("admin"))
			r.Post("/api/rules", HandleCreateRule(db, engine, logger))
			r.Put("/api/rules/{id}", HandleUpdateRule(db, engine, logger))
			r.Delete("/api/rules/{id}", HandleDeleteRule(db, engine, logger))
		})
	})

	return &Server{Router: r, cfg: cfg}
}
