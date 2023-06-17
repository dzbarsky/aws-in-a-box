package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"aws-in-a-box/services/kinesis"
)

func main() {
	kinesisPort := flag.Int("kinesisPort", -1, "Enable Kinesis service")

	flag.Parse()

	methodRegistry := make(map[string]http.HandlerFunc)

	if *kinesisPort != -1 {
		k := kinesis.New()
		for _, name := range []string{"some_stream"} {
			k.CreateStream(kinesis.CreateStreamInput{
				StreamName: name,
				ShardCount: 20,
			})
		}
		k.RegisterHTTPHandlers(methodRegistry)
	}
	addr := ":" + strconv.Itoa(*kinesisPort)

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
		fmt.Println(r.Method, r.URL.String(), target) //, r.Body)

		method, ok := methodRegistry[target]
		if !ok {
			fmt.Println("NOT FOUND")
			w.WriteHeader(404)
			return
		}
		method(w, r)
	})

	h2s := &http2.Server{}
	h1s := &http.Server{
		Addr:    addr,
		Handler: h2c.NewHandler(handler, h2s),
	}

	err := h1s.ListenAndServe()
	if err != nil {
		panic(err)
	}
}
