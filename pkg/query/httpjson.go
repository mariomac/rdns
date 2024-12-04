package query

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

func log() *slog.Logger {
	return slog.With("component", "query.HttpJsonServer")
}

type Store interface {
	GetHostnames(ip string) []string
}

type Response struct {
	Hostnames []string `json:"hostnames"`
	IP        string   `json:"ip"`
}

func HttpJsonServer(store Store, port int) error {
	return http.ListenAndServe(fmt.Sprintf(":%d", port), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := strings.Trim(r.URL.Path, "/")
		w.Header().Set("Content-Type", "application/json")
		resp := Response{
			Hostnames: store.GetHostnames(ip),
			IP:        ip,
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log().Error("encoding response", err)
		}
	}))
}
