package server

import (
	"encoding/json"
	"net/http"
)

const proxyErrorHeader = "X-Agent-Vault-Proxy-Error"

// jsonOK writes a 200 JSON response.
func jsonOK(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(data)
}

// jsonCreated writes a 201 JSON response.
func jsonCreated(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(data)
}

// jsonStatus writes a JSON response with the given status code.
func jsonStatus(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// proxyError writes a JSON error response with separate code and message fields.
// Sets X-Agent-Vault-Proxy-Error so SDK clients can distinguish broker errors
// from upstream responses that happen to share the same status code.
func proxyError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(proxyErrorHeader, "true")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "message": message})
}
