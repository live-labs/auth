package server

import (
	"encoding/json"
	"github.com/live-labs/auth"
	"net/http"
)

type RefreshHandler struct {
	Registry *auth.Registry
}

func (h *RefreshHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {

	if request.Header.Get("Content-Type") != "application/json" {
		writer.WriteHeader(http.StatusBadRequest)
		writer.Write([]byte("Bad request, expected json"))
		return
	}

	type RefreshRequest struct {
		Username     string `json:"username"`
		RefreshToken string `json:"refresh_token"`
	}

	r := &RefreshRequest{}

	err := json.NewDecoder(request.Body).Decode(r)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		writer.Write([]byte("Bad request, could not decode body"))
		return
	}

	if r.Username == "" || r.RefreshToken == "" {
		writer.WriteHeader(http.StatusBadRequest)
		writer.Write([]byte("Bad request, username and refresh token required"))
		return
	}

	token, err := h.Registry.Refresh(r.Username, r.RefreshToken)

	if err != nil {
		writer.WriteHeader(http.StatusUnauthorized)
		writer.Write([]byte(err.Error()))
		return
	}

	// write token to response in bearer format
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Authorization", "Bearer "+token)

	writer.WriteHeader(http.StatusOK)
	writer.Write([]byte("{}"))
}
