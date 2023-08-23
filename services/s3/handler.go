package s3

import (
	"encoding/xml"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"aws-in-a-box/awserrors"
)

func NewHandler(logger *slog.Logger, s3 *S3) func(w http.ResponseWriter, r *http.Request) bool {
	return func(w http.ResponseWriter, r *http.Request) bool {
		logger.Info("Handling S3 request", "method", r.Method, "url", r.URL)
		path := strings.Trim(r.URL.Path, "/")
		parts := strings.SplitN(path, "/", 2)

		if len(parts) == 1 {
			if r.URL.Query().Has("tagging") {
				switch r.Method {
				case http.MethodGet:
					handle(w, r, logger.With("method", "GetBucketTagging"), s3.GetBucketTagging)
				case http.MethodPut:
					handle(w, r, logger.With("method", "PutBucketTagging"), s3.PutBucketTagging)
				case http.MethodDelete:
					handle(w, r, logger.With("method", "DeleteBucketTagging"), s3.DeleteBucketTagging)
				default:
					panic("Unhandled method")
				}
				return true
			} else if r.URL.Query().Has("delete") {
				switch r.Method {
				case http.MethodPost:
					handle(w, r, logger.With("method", "DeleteObjects"), s3.DeleteObjects)
				default:
					panic("Unhandled method")
				}
				return true
			}
			switch r.Method {
			case http.MethodPut:
				handle(w, r, logger.With("method", "CreateBucket"), s3.CreateBucket)
			case http.MethodDelete:
				handle(w, r, logger.With("method", "DeleteBucket"), s3.DeleteBucket)
			case http.MethodHead:
				handle(w, r, logger.With("method", "HeadBucket"), s3.HeadBucket)
			// https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPOST.html
			case http.MethodPost:
				err := r.ParseMultipartForm(10 * 1024 * 1024)
				if err != nil {
					panic(err)
				}
				f, err := r.MultipartForm.File["file"][0].Open()
				if err != nil {
					panic(err)
				}
				input := PutObjectInput{
					Bucket:               parts[0],
					Key:                  r.Form.Get("key"),
					ServerSideEncryption: r.Form.Get("x-amz-server-side-encryption"),
					ContentType:          r.Form.Get("Content-Type"),
					Data:                 f,
				}
				logger.Debug("Parsed input", "method", "PutObject", "input", input)
				output, awserr := s3.PutObject(input)
				logger.Debug("Got output", "method", "PutObject", "output", output, "error", awserr)
				marshal(w, output, awserr)
			default:
				panic("Unhandled method")
			}
		}
		if len(parts) == 2 {
			if r.URL.Query().Has("tagging") {
				switch r.Method {
				case http.MethodGet:
					handle(w, r, logger.With("method", "GetObjectTagging"), s3.GetObjectTagging)
				case http.MethodPut:
					handle(w, r, logger.With("method", "PutObjectTagging"), s3.PutObjectTagging)
				case http.MethodDelete:
					handle(w, r, logger.With("method", "DeleteObjectTagging"), s3.DeleteObjectTagging)
				default:
					panic("Unhandled method")
				}
				return true
			} else if r.URL.Query().Has("uploads") {
				switch r.Method {
				case http.MethodPost:
					handle(w, r, logger.With("method", "CreateMultipartUpload"), s3.CreateMultipartUpload)
				default:
					panic("Unhandled method")
				}
				return true
			} else if r.URL.Query().Has("uploadId") {
				switch r.Method {
				case http.MethodPut:
					handle(w, r, logger.With("method", "UploadPart"), s3.UploadPart)
				case http.MethodPost:
					handle(w, r, logger.With("method", "CompleteMultipartUpload"), s3.CompleteMultipartUpload)
				case http.MethodDelete:
					handle(w, r, logger.With("method", "AbortMultipartUpload"), s3.AbortMultipartUpload)
				case http.MethodGet:
					handle(w, r, logger.With("method", "ListParts"), s3.ListParts)
				default:
					panic("Unhandled method")
				}
				return true
			}
			switch r.Method {
			case http.MethodGet:
				handle(w, r, logger.With("method", "GetObject"), s3.GetObject)
			case http.MethodHead:
				handle(w, r, logger.With("method", "HeadObject"), s3.HeadObject)
			case http.MethodPut:
				if r.Header.Get("x-amz-copy-source") != "" {
					handle(w, r, logger.With("method", "CopyObject"), s3.CopyObject)
				} else {
					handle(w, r, logger.With("method", "PutObject"), s3.PutObject)
				}
			case http.MethodDelete:
				handle(w, r, logger.With("method", "DeleteObject"), s3.DeleteObject)
			default:
				panic("Unhandled method")
			}
		}
		return true
	}
}

func handle[Input any, Output any](
	w http.ResponseWriter,
	r *http.Request,
	logger *slog.Logger,
	handler func(input Input) (*Output, *awserrors.Error),
) {
	var input Input
	err := unmarshal(r, &input)
	if err != nil {
		logger.Error("Unmarshaling input", "err", err)
		panic(err)
	}
	logger.Debug("Parsed input", "input", input)

	output, awserr := handler(input)
	logger.Debug("Got output", "output", output, "error", awserr)

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

		f := v.Field(i)
		if tag == "bucket" {
			f.Set(reflect.ValueOf(parts[0]))
		} else if tag == "key" {
			f.Set(reflect.ValueOf(parts[1]))
		} else if tag == "body" {
			f.Set(reflect.ValueOf(r.Body))
		} else if q, ok := strings.CutPrefix(tag, "query:"); ok {
			v := r.URL.Query().Get(q)

			isPointer := false
			kind := field.Type.Kind()
			if kind == reflect.Pointer {
				if v == "" {
					continue
				}
				isPointer = true
				kind = field.Type.Elem().Kind()
			}

			if kind == reflect.Int {
				ival, err := strconv.Atoi(v)
				if err != nil {
					panic(err)
				}
				if isPointer {
					f.Set(reflect.ValueOf(&ival))
				} else {
					f.Set(reflect.ValueOf(ival))
				}
			} else {
				if isPointer {
					f.Set(reflect.ValueOf(&v))
				} else {
					f.Set(reflect.ValueOf(v))
				}
			}
		} else if h, ok := strings.CutPrefix(tag, "header:"); ok {
			f.Set(reflect.ValueOf(r.Header.Get(h)))
		}
	}
	return nil
}

func marshal(w http.ResponseWriter, output any, awserr *awserrors.Error) {
	var body io.Reader
	if awserr != nil {
		w.WriteHeader(awserr.Code)
		w.Write([]byte(awserr.Body.Message))
	} else {
		v := reflect.ValueOf(output).Elem()
		ty := v.Type()
		for i := 0; i < ty.NumField(); i++ {
			tag := ty.Field(i).Tag.Get("s3")
			if tag == "body" {
				reflect.ValueOf(&body).Elem().Set(v.Field(i))
			} else if h, ok := strings.CutPrefix(tag, "header:"); ok {
				field := ty.Field(i)
				switch field.Type.Kind() {
				case reflect.Int, reflect.Int64:
					w.Header().Set(h, strconv.Itoa(int(v.Field(i).Int())))
				default:
					w.Header().Set(h, v.Field(i).String())
				}
			}
		}

		if output == response204 {
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(http.StatusOK)
		}

		if body != nil {
			_, err := io.Copy(w, body)
			if err != nil {
				panic(err)
			}
		} else if _, ok := ty.FieldByName("XMLName"); ok {
			err := xml.NewEncoder(w).Encode(output)
			if err != nil {
				panic(err)
			}
		}
	}
}
