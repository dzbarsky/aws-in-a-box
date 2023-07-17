package s3

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"aws-in-a-box/awserrors"
)

func writeXML(w io.Writer, output any) {
	err := xml.NewEncoder(w).Encode(output)
	if err != nil {
		panic(err)
	}
}

func NewHandler(s3 *S3) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//log.Print("Handling S3 request ", r.Method, " ", r.URL.String())
		path := strings.Trim(r.URL.Path, "/")
		parts := strings.SplitN(path, "/", 2)

		if len(parts) == 1 {
			if r.URL.Query().Has("tagging") {
				switch r.Method {
				case http.MethodGet:
					handle(w, r, s3.GetBucketTagging)
				case http.MethodPut:
					handle(w, r, s3.PutBucketTagging)
				case http.MethodDelete:
					handle(w, r, s3.DeleteBucketTagging)
				}
				return
			}
			switch r.Method {
			case http.MethodPut:
				handle(w, r, s3.CreateBucket)
			case http.MethodDelete:
				handle(w, r, s3.DeleteBucket)
			}
		}
		if len(parts) == 2 {
			if r.URL.Query().Has("tagging") {
				switch r.Method {
				case http.MethodGet:
					handle(w, r, s3.GetObjectTagging)
				case http.MethodPut:
					handle(w, r, s3.PutObjectTagging)
				case http.MethodDelete:
					handle(w, r, s3.DeleteObjectTagging)
				}
				return
			} else if r.URL.Query().Has("uploads") {
				switch r.Method {
				case http.MethodGet:
					panic("Unhandled GetMultipartUploads")
				case http.MethodPost:
					handle(w, r, s3.CreateMultipartUpload)
				}
				return
			} else if r.URL.Query().Has("uploadId") {
				switch r.Method {
				case http.MethodPut:
					handle(w, r, s3.UploadPart)
				case http.MethodPost:
					handle(w, r, s3.CompleteMultipartUpload)
				case http.MethodDelete:
					handle(w, r, s3.AbortMultipartUpload)
				}
				return
			}
			switch r.Method {
			case http.MethodGet:
				object, err := s3.GetObject(parts[0], parts[1])
				w.Header().Set("Content-Type", object.ContentType)
				w.Header().Set("x-amz-server-side-encryption", object.ServerSideEncryption)
				w.Header().Set("x-amz-server-side-encryption-customer-key", object.SSECustomerKey)
				w.Header().Set("x-amz-server-side-encryption-customer-algorithm", object.SSECustomerAlgorithm)
				w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", object.SSEKMSKeyId)
				w.Header().Set("Content-Length", strconv.Itoa(len(object.Data)))
				w.Header().Set("Accept-Ranges", "bytes")
				if err != nil {
					w.WriteHeader(err.Code)
					w.Write([]byte(err.Body.Message))
				} else {
					w.WriteHeader(http.StatusOK)
					w.Write(object.Data)
				}
			case http.MethodHead:
				object, err := s3.GetObject(parts[0], parts[1])
				w.Header().Set("Content-Type", object.ContentType)
				w.Header().Set("x-amz-server-side-encryption", object.ServerSideEncryption)
				w.Header().Set("x-amz-server-side-encryption-customer-algorithm", object.SSECustomerAlgorithm)
				w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", object.SSEKMSKeyId)
				w.Header().Set("Accept-Ranges", "bytes")
				if err != nil {
					w.WriteHeader(err.Code)
					w.Write([]byte(err.Body.Message))
				} else {
					w.WriteHeader(http.StatusOK)
				}
			case http.MethodPut:
				if r.Header.Get("x-amz-copy-source") != "" {
					handle(w, r, s3.CopyObject)
				} else {
					handle(w, r, s3.PutObject)
				}
			case http.MethodDelete:
				handle(w, r, s3.DeleteObject)
			default:
				panic("unknown method")
			}
		}
	})
}

func handle[Input any, Output any](
	w http.ResponseWriter,
	r *http.Request,
	handler func(input Input) (*Output, *awserrors.Error),
) {
	var input Input
	err := unmarshal(r, &input)
	if err != nil {
		panic(err)
	}
	output, awserr := handler(input)
	marshal(w, output, awserr)
}

func unmarshal(r *http.Request, target any) error {
	path := strings.Trim(r.URL.Path, "/")
	parts := strings.SplitN(path, "/", 2)

	v := reflect.ValueOf(target).Elem()
	ty := v.Type()

	if _, ok := ty.FieldByName("XMLName"); ok {
		err := xml.NewDecoder(r.Body).Decode(target)
		if err != nil && err != io.EOF {
			return err
		}
	}

	for i := 0; i < ty.NumField(); i++ {
		field := ty.Field(i)
		tag := field.Tag.Get("s3")
		if tag == "" {
			continue
		}

		var value any
		if tag == "bucket" {
			value = parts[0]
		} else if tag == "key" {
			value = parts[1]
		} else if tag == "body" {
			var err error
			value, err = io.ReadAll(r.Body)
			if err != nil {
				panic(err)
			}
			defer r.Body.Close()
		} else if q, ok := strings.CutPrefix(tag, "query:"); ok {
			v := r.URL.Query().Get(q)
			if field.Type.Kind() == reflect.Int {
				var err error
				value, err = strconv.Atoi(v)
				if err != nil {
					panic(err)
				}
			} else {
				value = v
			}
		} else if h, ok := strings.CutPrefix(tag, "header:"); ok {
			value = r.Header.Get(h)
		}
		v.Field(i).Set(reflect.ValueOf(value))
	}
	return nil
}

func marshal(w http.ResponseWriter, output any, awserr *awserrors.Error) {
	if awserr != nil {
		fmt.Println("ERRR", awserr)
		w.WriteHeader(awserr.Code)
		w.Write([]byte(awserr.Body.Message))
	} else {
		v := reflect.ValueOf(output).Elem()
		ty := v.Type()
		for i := 0; i < ty.NumField(); i++ {
			tag := ty.Field(i).Tag.Get("s3")
			if h, ok := strings.CutPrefix(tag, "header:"); ok {
				w.Header().Set(h, v.Field(i).String())
			}
		}

		if output == response204 {
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(http.StatusOK)
		}

		if _, ok := ty.FieldByName("XMLName"); ok {
			writeXML(w, output)
		}
	}
}
