package server

import (
	"encoding/json"
	"github.com/live-labs/auth"
	"net/http"
)

type LoginHandler struct {
	Registry *auth.Registry
}

func (h *LoginHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {

	if request.Header.Get("Content-Type") != "application/json" {
		writer.WriteHeader(http.StatusBadRequest)
		writer.Write([]byte("Bad request, expected json"))
		return
	}

	type LoginRequest struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	r := &LoginRequest{}

	err := json.NewDecoder(request.Body).Decode(r)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		writer.Write([]byte("Bad request, could not decode body"))
		return
	}

	if r.Username == "" || r.Password == "" {
		writer.WriteHeader(http.StatusBadRequest)
		writer.Write([]byte("Bad request, username and password required"))
		return
	}

	accessToken, refreshToken, err := h.Registry.Login(r.Username, r.Password)
	if err != nil {
		writer.WriteHeader(http.StatusUnauthorized)
		writer.Write([]byte(err.Error()))
		return
	}

	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Authorization", "Bearer "+accessToken)

	type LoginResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	writer.WriteHeader(http.StatusOK)

	json.NewEncoder(writer).Encode(&LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken, // logout should remove this accessToken
	})
}
