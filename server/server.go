package server

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"

	"github.com/gofrs/uuid/v5"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func New(handler http.HandlerFunc) *http.Server {
	h2s := &http2.Server{}
	return &http.Server{
		Handler: h2c.NewHandler(handler, h2s),
	}
}

type HandlerFunc = func(w http.ResponseWriter, r *http.Request) bool

func NewWithHandlerChain(chain ...HandlerFunc) *http.Server {
	return New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, handler := range chain {
			if handler(w, r) {
				break
			}
		}
	}))
}

func HandlerFuncFromRegistry(logger *slog.Logger, registry map[string]http.HandlerFunc) HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) bool {
		buf, err := io.ReadAll(r.Body)
		if err != nil {
			logger.Error("Reading body", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
		}
		r.Body = io.NopCloser(bytes.NewBuffer(buf))

		// The target endpoint is specified in the `X-Amz-Target` header.
		// If it's missing, this request is for S3.
		target := r.Header.Get("X-Amz-Target")
		if target == "" {
			return false
		}

		w.Header().Add("x-amzn-RequestId", uuid.Must(uuid.NewV4()).String())
		method, ok := registry[target]
		if !ok {
			logger.Error("Method not found", "method", method)
			w.WriteHeader(404)
			return true
		}

		method(w, r)
		return true
	}
}
