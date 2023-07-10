package server

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/gofrs/uuid/v5"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func New(methodRegistry map[string]http.HandlerFunc) *http.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, err := io.ReadAll(r.Body)
		if err != nil {
			log.Print("bodyErr ", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		r.Body = io.NopCloser(bytes.NewBuffer(buf))

		// The target endpoint is specified in the `X-Amz-Target` header.
		target := r.Header.Get("X-Amz-Target")
		//log.Println(r.Method, r.URL.String(), target) //, r.Body)

		w.Header().Add("x-amzn-RequestId", uuid.Must(uuid.NewV4()).String())
		method, ok := methodRegistry[target]
		if !ok {
			fmt.Println("NOT FOUND")
			w.WriteHeader(404)
			return
		}
		method(w, r)
	})

	h2s := &http2.Server{}
	return &http.Server{
		Handler: h2c.NewHandler(handler, h2s),
	}
}
