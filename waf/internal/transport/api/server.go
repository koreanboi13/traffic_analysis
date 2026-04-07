package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	apimw "github.com/koreanboi13/traffic_analysis/waf/internal/transport/api/middleware"
	"github.com/rs/cors"
	"go.uber.org/zap"
)

// Server holds the Admin API router.
type Server struct {
	Router chi.Router
}

// NewServer creates a new Admin API server with all routes, CORS, JWT, and RBAC middleware.
// Public route: POST /api/auth/login
// Authenticated routes (Analyst + Admin): GET /api/rules, GET /api/rules/{id}, GET /api/events
// Admin-only routes: POST /api/rules, PUT /api/rules/{id}, DELETE /api/rules/{id}
func NewServer(
	ruleService RuleService,
	authService AuthService,
	eventService EventService,
	jwtSecret []byte,
	allowedOrigins []string,
	logger *zap.Logger,
) *Server {
	r := chi.NewRouter()

	// Standard chi middleware
	r.Use(chimw.RequestID)
	r.Use(chimw.Recoverer)

	// CORS for React panel (panel may run on a different origin)
	if len(allowedOrigins) == 0 {
		allowedOrigins = []string{"http://localhost:5173", "http://localhost:3000"}
	}
	c := cors.New(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	})
	r.Use(c.Handler)

	// Public route: login (no JWT required)
	r.Post("/api/auth/login", HandleLogin(authService, logger))

	// Health check
	r.Get("/api/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Authenticated routes
	r.Group(func(r chi.Router) {
		r.Use(apimw.JWTMiddleware(jwtSecret))

		// Analyst + Admin: read rules and events
		r.Get("/api/rules", HandleListRules(ruleService, logger))
		r.Get("/api/rules/{id}", HandleGetRule(ruleService, logger))
		r.Get("/api/events", HandleListEvents(eventService, logger))
		r.Post("/api/events/export", HandleExportEvents(eventService, logger))

		// Admin only: mutate rules
		r.Group(func(r chi.Router) {
			r.Use(apimw.RequireRole("admin"))
			r.Post("/api/rules", HandleCreateRule(ruleService, logger))
			r.Put("/api/rules/{id}", HandleUpdateRule(ruleService, logger))
			r.Delete("/api/rules/{id}", HandleDeleteRule(ruleService, logger))
		})
	})

	return &Server{Router: r}
}
