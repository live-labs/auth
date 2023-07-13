package server

import (
	"encoding/json"
	"github.com/live-labs/auth"
	"net/http"
)

type UnblacklistHandler struct {
	Registry *auth.Registry
}

func (h *UnblacklistHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {

	if request.Header.Get("Content-Type") != "application/json" {
		writer.WriteHeader(http.StatusBadRequest)
		writer.Write([]byte("Bad request, expected json"))
		return
	}

	type UnBlacklistRequest struct {
		Username string `json:"username"`
	}

	r := &UnBlacklistRequest{}

	err := json.NewDecoder(request.Body).Decode(r)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		writer.Write([]byte("Bad request, could not decode body"))
		return
	}

	if r.Username == "" {
		writer.WriteHeader(http.StatusBadRequest)
		writer.Write([]byte("Bad request, username required"))
		return
	}

	err = h.Registry.Unblacklist(r.Username)

	if err != nil {
		writer.WriteHeader(http.StatusNotFound)
		writer.Write([]byte(err.Error()))
		return
	}

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	writer.Write([]byte("{}"))
}
