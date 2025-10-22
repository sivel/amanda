// (c) Matt Martz <matt@sivel.net>
// GNU General Public License v3.0+
//     (see https://www.gnu.org/licenses/gpl-3.0.txt)

package utils

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

var loggedErrors sync.Map

func LogErrOnce[T any](val T, err error) (T, error) {
	if err != nil {
		if _, exists := loggedErrors.LoadOrStore(err.Error(), true); !exists {
			log.Printf("error: %v", err)
		}
	}
	return val, err
}

func DecodeBase64ToBuffer(r io.Reader) (*bytes.Reader, error) {
	decoder := base64.NewDecoder(base64.StdEncoding, r)

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, decoder); err != nil {
		return nil, err
	}

	return bytes.NewReader(buf.Bytes()), nil
}

func PrepareFormFile(file *multipart.FileHeader) (io.ReadSeeker, error) {
	src, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer src.Close()

	var srcBuf io.ReadSeeker
	cte := file.Header.Get("Content-Transfer-Encoding")
	if cte == "base64" {
		srcBuf, _ = DecodeBase64ToBuffer(src)
	} else {
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, src); err != nil {
			return nil, err
		}
		srcBuf = bytes.NewReader(buf.Bytes())
	}

	return srcBuf, nil
}

func Indent(text string, prefix string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if len(line) > 0 {
			lines[i] = prefix + line
		}
	}
	return strings.Join(lines, "\n")
}

type LogWriter struct {
	gin.ResponseWriter
	Body *bytes.Buffer
}

func (w LogWriter) Write(b []byte) (int, error) {
	w.Body.Write(b)
	return w.ResponseWriter.Write(b)
}

func LogStatusContext() gin.HandlerFunc {
	return func(c *gin.Context) {
		logWriter := &LogWriter{Body: new(bytes.Buffer), ResponseWriter: c.Writer}
		c.Writer = logWriter

		c.Next()

		switch c.Writer.Status() {
		case http.StatusBadRequest:
			body := Indent(logWriter.Body.String(), "    ")
			log.Printf("400 Bad Request: %s %s\n%s", c.Request.Method, c.Request.URL.Path, body)
		}
	}
}

func MaxBodySize(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > maxBytes {
			c.AbortWithStatus(http.StatusRequestEntityTooLarge)
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}

func GetSha256Digest(file io.ReadSeeker) (string, error) {
	defer file.Seek(0, io.SeekStart)
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func LoadFilesFromTar(file io.ReadSeeker, caseInsensitive bool, filenames ...string) (map[string][]byte, error) {
	defer file.Seek(0, io.SeekStart)

	// If caseInsensitive, caller must pass lowercase filenames
	fileMap := make(map[string]struct{}, len(filenames))
	for _, name := range filenames {
		fileMap[name] = struct{}{}
	}

	result := make(map[string][]byte)

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	for {
		header, err := tarReader.Next()

		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, err
		}

		name := header.Name
		if caseInsensitive {
			name = strings.ToLower(name)
		}

		if _, ok := fileMap[name]; ok {
			data := make([]byte, header.Size)
			_, err := io.ReadFull(tarReader, data)
			if err != nil {
				return nil, err
			}
			result[name] = data

			if len(result) == len(filenames) {
				break
			}
		}
	}

	return result, nil
}
