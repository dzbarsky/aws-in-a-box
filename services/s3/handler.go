package s3

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
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

		if len(parts) == 2 {
			if r.URL.Query().Has("tagging") {
				switch r.Method {
				case "GET":
					tagging, err := s3.GetObjectTagging(parts[0], parts[1])
					if err != nil {
						fmt.Println("ERRR", err)
						w.WriteHeader(err.Code)
						w.Write([]byte(err.Body.Message))
					} else {
						w.WriteHeader(http.StatusOK)
						writeXML(w, tagging.Tagging)
					}
				case "PUT":
					var tagging Tagging
					// TODO: better decoding?
					err := xml.NewDecoder(r.Body).Decode(&tagging)
					if err != nil {
						panic(err)
					}
					_, awserr := s3.PutObjectTagging(PutObjectTaggingInput{
						Bucket:  parts[0],
						Key:     parts[1],
						Tagging: tagging,
					})
					if awserr != nil {
						w.WriteHeader(awserr.Code)
						w.Write([]byte(awserr.Body.Message))
					} else {
						w.WriteHeader(http.StatusOK)
					}
				}
				return
			} else if r.URL.Query().Has("uploads") {
				switch r.Method {
				case http.MethodGet:
					panic("Unhandled GetMultipartUploads")
				case http.MethodPost:
					output, awserr := s3.CreateMultipartUpload(
						parts[0],
						parts[1],
						r.Header)
					if awserr != nil {
						w.WriteHeader(awserr.Code)
						w.Write([]byte(awserr.Body.Message))
					} else {
						w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", output.SSEKMSKeyId)
						w.Header().Set("x-amz-server-side-encryption-context", output.SSEKMSEncryptionContext)
						w.WriteHeader(http.StatusOK)
						writeXML(w, output)
					}
				}
				return
			} else if r.URL.Query().Has("uploadId") {
				switch r.Method {
				case http.MethodPut:
					data, err := io.ReadAll(r.Body)
					if err != nil {
						panic(err)
					}
					defer r.Body.Close()
					partNumber, err := strconv.Atoi(r.URL.Query().Get("partNumber"))
					if err != nil {
						panic(err)
					}

					output, awserr := s3.UploadPart(UploadPartInput{
						Bucket:     parts[0],
						Key:        parts[1],
						UploadId:   r.URL.Query().Get("uploadId"),
						PartNumber: partNumber,
						Data:       data,
					})
					if awserr != nil {
						w.WriteHeader(awserr.Code)
						w.Write([]byte(awserr.Body.Message))
					} else {
						w.Header().Set("ETag", output.ETag)
						w.Header().Set("x-amz-server-side-encryption", output.ServerSideEncryption)
						w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", output.SSEKMSKeyId)
						w.WriteHeader(http.StatusOK)
					}

				case http.MethodPost:
					var input CompleteMultipartUploadInput
					// TODO: better decoding?
					err := xml.NewDecoder(r.Body).Decode(&input)
					if err != nil {
						panic(err)
					}
					input.Bucket = parts[0]
					input.Key = parts[1]
					input.UploadId = r.URL.Query().Get("uploadId")
					output, awserr := s3.CompleteMultipartUpload(input)
					if awserr != nil {
						w.WriteHeader(awserr.Code)
						w.Write([]byte(awserr.Body.Message))
					} else {
						w.Header().Set("x-amz-server-side-encryption", output.ServerSideEncryption)
						w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", output.SSEKMSKeyId)
						w.Header().Set("x-amz-server-side-encryption-context", output.SSEKMSEncryptionContext)
						w.WriteHeader(http.StatusOK)
						writeXML(w, output)
						writeXML(os.Stdout, output)
					}
				}
				return
			}
			switch r.Method {
			case http.MethodGet:
				object, err := s3.GetObject(parts[0], parts[1])
				w.Header().Set("Content-Type", object.ContentType)
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
				var awserr *awserrors.Error
				var output *CopyObjectOutput
				if r.Header.Get("x-amz-copy-source") != "" {
					output, awserr = s3.CopyObject(parts[0], parts[1], r.Header)
				} else {
					data, err := io.ReadAll(r.Body)
					if err != nil {
						panic(err)
					}
					defer r.Body.Close()
					awserr = s3.PutObject(parts[0], parts[1], data, r.Header)
				}
				if awserr != nil {
					panic(awserr)
				}
				w.WriteHeader(http.StatusOK)
				if output != nil {
					writeXML(w, output)
				}
			case http.MethodDelete:
				err := s3.DeleteObject(parts[0], parts[1])
				if err != nil {
					panic(err)
				}
			default:
				panic("unknown method")
			}
		}
	})
}
