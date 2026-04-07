package admin

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/koreanboi13/traffic_analysis/waf/internal/app/admin/handler"
	"github.com/koreanboi13/traffic_analysis/waf/internal/app/admin/middleware"
	"github.com/rs/cors"
	"go.uber.org/zap"
)

// NewRouter creates a chi.Router for the Admin API with all routes, CORS, JWT, and RBAC.
func NewRouter(
	ruleService handler.RuleService,
	authService handler.AuthService,
	eventService handler.EventService,
	jwtSecret []byte,
	allowedOrigins []string,
	logger *zap.Logger,
) chi.Router {
	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	r.Use(chimw.Recoverer)

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

	// Public routes
	r.Post("/api/auth/login", handler.HandleLogin(authService, logger))
	r.Get("/api/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Authenticated routes
	r.Group(func(r chi.Router) {
		r.Use(middleware.JWTMiddleware(jwtSecret))

		r.Get("/api/rules", handler.HandleListRules(ruleService, logger))
		r.Get("/api/rules/{id}", handler.HandleGetRule(ruleService, logger))
		r.Get("/api/events", handler.HandleListEvents(eventService, logger))
		r.Post("/api/events/export", handler.HandleExportEvents(eventService, logger))

		// Admin only
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireRole("admin"))
			r.Post("/api/rules", handler.HandleCreateRule(ruleService, logger))
			r.Put("/api/rules/{id}", handler.HandleUpdateRule(ruleService, logger))
			r.Delete("/api/rules/{id}", handler.HandleDeleteRule(ruleService, logger))
		})
	})

	return r
}
