// (c) Matt Martz <matt@sivel.net>
// GNU General Public License v3.0+
//     (see https://www.gnu.org/licenses/gpl-3.0.txt)

package models

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	semver "github.com/Masterminds/semver/v3"
	"github.com/gin-gonic/gin"
	"github.com/sivel/amanda/utils"
	"golang.org/x/sys/unix"
	yaml "gopkg.in/yaml.v3"
)

const XattrName = "user.amanda"
const ISO8601 = "2006-01-02T15:04:05.000000-0700"

type CollectionInfo struct {
	Namespace     string          `json:"namespace"`
	Name          string          `json:"name"`
	Version       *semver.Version `json:"version"`
	Dependencies  gin.H           `json:"dependencies"`
	Repository    string          `json:"repository"`
	Documentation string          `json:"documentation"`
	Homepage      string          `json:"homepage"`
	Issues        string          `json:"issues"`
	Tags          []string        `json:"tags"`
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

	files, err := utils.LoadFilesFromTar(file, false, "MANIFEST.json", "meta/runtime.yml")
	if err != nil {
		return nil, fmt.Errorf("manifest: %s %s", path, err)
	}

	manifestData, ok := files["MANIFEST.json"]
	if !ok {
		return nil, fmt.Errorf("MANIFEST.json not found in %s", path)
	}

	err = json.Unmarshal(manifestData, &collection)
	if err != nil {
		return nil, fmt.Errorf("manifest: %s %s", path, err)
	}

	if runtimeData, ok := files["meta/runtime.yml"]; ok {
		var runtime CollectionRuntime
		if err := yaml.Unmarshal(runtimeData, &runtime); err == nil {
			collection.RequiresAnsible = runtime.RequiresAnsible
		}
	}

	collection.Sha, err = utils.GetSha256Digest(file)
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
