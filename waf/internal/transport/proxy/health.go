package proxy

import (
	"encoding/json"
	"net/http"
)

// HealthHandler returns an http.HandlerFunc that responds with HTTP 200
// and a JSON body {"status":"ok"}.
func HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}
}
