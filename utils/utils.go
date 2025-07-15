// (c) Matt Martz <matt@sivel.net>
// GNU General Public License v3.0+
//     (see https://www.gnu.org/licenses/gpl-3.0.txt)

package utils

import (
	"bytes"
	"encoding/base64"
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
