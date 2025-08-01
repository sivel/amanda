// (c) Matt Martz <matt@sivel.net>
// GNU General Public License v3.0+
//     (see https://www.gnu.org/licenses/gpl-3.0.txt)

package models

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	semver "github.com/Masterminds/semver/v3"
	"github.com/gin-gonic/gin"
	"golang.org/x/sys/unix"
	yaml "gopkg.in/yaml.v3"
)

const XattrName = "user.amanda"
const ISO8601 = "2006-01-02T15:04:05.000000-0700"

type CollectionInfo struct {
	Namespace    string          `json:"namespace"`
	Name         string          `json:"name"`
	Version      *semver.Version `json:"version"`
	Dependencies gin.H           `json:"dependencies"`
}

type CollectionRuntime struct {
	RequiresAnsible string `json:"requires_ansible" yaml:"requires_ansible"`
}

type Collection struct {
	Filename        string
	Path            string
	Sha             string
	Created         string         `json:"created"`
	CollectionInfo  CollectionInfo `json:"collection_info"`
	RequiresAnsible string         `json:"requires_ansible"`
	mutex           sync.Mutex
}

func (c *Collection) Mutex() *sync.Mutex {
	return &c.mutex
}

func (c *Collection) Matches(namespace string, name string, version string) bool {
	if namespace == "" && name == "" {
		return true
	}

	if c.CollectionInfo.Namespace != namespace || c.CollectionInfo.Name != name {
		return false
	}

	if version == "" {
		return true
	}

	return c.CollectionInfo.Version.String() == version
}

func ValidateCollection(collection *Collection, expectedSha256 string) error {
	if !strings.EqualFold(collection.Sha, expectedSha256) {
		return fmt.Errorf("checksum mismatch")
	}

	ci := collection.CollectionInfo

	if !validateName(ci.Namespace) {
		return fmt.Errorf("invalid namespace")
	}
	if !validateName(ci.Name) {
		return fmt.Errorf("invalid name")
	}

	return nil
}

func validateName(s string) bool {
	if len(s) < 2 {
		return false
	}

	b := s[0]
	if b < 'a' || b > 'z' {
		return false
	}

	for i := 1; i < len(s); i++ {
		b := s[i]
		if !(('a' <= b && b <= 'z') || ('0' <= b && b <= '9') || b == '_') {
			return false
		}
	}

	return true
}

func getSha256Digest(file io.ReadSeeker) (string, error) {
	defer file.Seek(0, io.SeekStart)
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func loadFilesFromTar(file io.ReadSeeker) (*Collection, error) {
	defer file.Seek(0, io.SeekStart)

	var collection *Collection
	var runtime *CollectionRuntime

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return collection, err
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	foundManifest := false
	foundRuntime := false
	for {
		header, err := tarReader.Next()

		if err == io.EOF {
			break
		}

		if err != nil {
			return collection, err
		}

		name := strings.ToLower(header.Name)

		switch name {
		case "manifest.json", "./manifest.json":
			if foundManifest {
				continue
			}
			foundManifest = true
			data := make([]byte, header.Size)
			_, err := tarReader.Read(data)
			if err != io.EOF && err != nil {
				return collection, err
			}
			err = json.Unmarshal(data, &collection)
			if err != nil {
				return collection, err
			}
		case "meta/runtime.yml", "./meta/runtime.yml":
			if foundRuntime {
				continue
			}
			foundRuntime = true
			data := make([]byte, header.Size)
			_, err := tarReader.Read(data)
			if err == io.EOF || err == nil {
				yaml.Unmarshal(data, &runtime)
			}
		}

		if foundManifest && foundRuntime {
			break
		}

	}

	if runtime != nil {
		collection.RequiresAnsible = runtime.RequiresAnsible
	}

	return collection, nil
}

func CollectionFromTar(path string, file io.ReadSeeker) (*Collection, error) {
	var collection *Collection
	var err error

	if file == nil {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		file = f
	}

	collection, err = loadFilesFromTar(file)
	if err != nil {
		return nil, fmt.Errorf("manifest: %s %s", path, err)
	}
	collection.Sha, err = getSha256Digest(file)
	if err != nil {
		return nil, fmt.Errorf("sha256: %s %s", path, err)
	}

	return collection, nil
}

func CollectionFromXattr(path string, xattrs bool) (*Collection, error) {
	if !xattrs {
		return nil, fmt.Errorf("xattrs not enabled")
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	size, err := unix.Fgetxattr(int(f.Fd()), XattrName, nil)
	if err != nil {
		return nil, fmt.Errorf("xattr %s on %s %s", XattrName, path, err)
	}

	buf := make([]byte, size)
	_, err = unix.Fgetxattr(int(f.Fd()), XattrName, buf)
	if err != nil {
		return nil, fmt.Errorf("xattr %s on %s %s", XattrName, path, err)
	}

	var collection Collection
	if err := json.Unmarshal(buf, &collection); err != nil {
		return nil, err
	}

	createdTime, err := time.Parse(ISO8601, collection.Created)
	if err != nil {
		return nil, fmt.Errorf("unable to parse cache created date on %s: %s", path, err)
	}

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	modTime := info.ModTime().Truncate(time.Microsecond)

	if !modTime.Equal(createdTime) {
		unix.Fremovexattr(int(f.Fd()), XattrName)
		return nil, fmt.Errorf("modtime mismatch on %s: %s != %s", path, createdTime, modTime)
	}

	return &collection, nil
}
