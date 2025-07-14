// (c) Matt Martz <matt@sivel.net>
// GNU General Public License v3.0+
//     (see https://www.gnu.org/licenses/gpl-3.0.txt)

package storage

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/sivel/amanda/models"
	"github.com/sivel/amanda/utils"
)

type CacheKey struct {
	Filename string
	Modtime  string
}

type Storage struct {
	artifacts string
	xattrs    bool
	cache     sync.Map
}

func New(artifacts string, xattrs bool) *Storage {
	return &Storage{
		artifacts: artifacts,
		xattrs:    xattrs,
	}
}

func (s *Storage) cacheKey(filename string, modtime time.Time) CacheKey {
	return CacheKey{
		Filename: filename,
		Modtime:  modtime.Format(models.ISO8601),
	}
}

func (s *Storage) store(filename string, modtime time.Time, collection *models.Collection) {
	key := s.cacheKey(filename, modtime)
	s.cache.Store(key, collection)
}

func (s *Storage) load(filename string, modtime time.Time) (*models.Collection, bool) {
	key := s.cacheKey(filename, modtime)
	val, ok := s.cache.Load(key)
	if ok {
		return val.(*models.Collection), ok
	}
	return nil, ok
}

func (s *Storage) Read(namespace string, name string, version string) ([]*models.Collection, error) {
	var collections []*models.Collection

	files, err := os.ReadDir(s.artifacts)
	if err != nil {
		return collections, err
	}

	for _, entry := range files {
		fileInfo, err := entry.Info()
		if err != nil {
			continue
		}

		var collection *models.Collection
		filename := fileInfo.Name()
		path := filepath.Join(s.artifacts, filename)
		if !strings.HasSuffix(filename, ".tar.gz") {
			continue
		}
		stem := filename[:len(filename)-7]
		signatureFilename := stem + ".asc"
		modtime := fileInfo.ModTime()
		if val, ok := s.load(filename, modtime); ok {
			collection = val
		} else if val, _ := models.CollectionFromXattr(path, s.xattrs); val != nil {
			collection = val
			collection.Filename = filename
			collection.Path = path
			s.store(filename, modtime, collection)
		} else {
			collection, err = utils.LogErrOnce(models.CollectionFromTar(path, nil))
			if err != nil {
				continue
			}

			collection.Filename = filename
			collection.Path = path
			collection.Created = modtime.Format(models.ISO8601)

			signature, err := os.ReadFile(filepath.Join(s.artifacts, signatureFilename))
			if err == nil {
				collectionSignature := models.CollectionSignature{Signature: string(signature)}
				collection.Signatures = append(collection.Signatures, collectionSignature)
			}
			s.store(filename, modtime, collection)
			if s.xattrs {
				s.WriteXattr(collection)
			}
		}

		if collection != nil && collection.Matches(namespace, name, version) {
			collections = append(collections, collection)
			if version != "" {
				break
			}
		}
	}

	return collections, nil
}

func (s *Storage) Write(sha256 string, filename string, src io.ReadSeeker) (string, error) {
	collection, err := utils.LogErrOnce(models.CollectionFromTar(filename, src))
	if err != nil {
		return "", err
	}

	err = models.ValidateCollection(collection, sha256)
	if err != nil {
		return "", err
	}

	ci := collection.CollectionInfo
	dstName := fmt.Sprintf("%s-%s-%s.tar.gz", ci.Namespace, ci.Name, ci.Version.String())
	dstPath := filepath.Join(s.artifacts, dstName)

	if s.Exists(dstName) {
		return "", fmt.Errorf("collection version already exists")
	}

	dst, err := os.Create(dstPath)
	if err != nil {
		return "", err
	}
	defer dst.Close()

	src.Seek(0, io.SeekStart)
	_, err = io.Copy(dst, src)
	if err != nil {
		return "", err
	}

	return dstName, nil
}

func (s *Storage) WriteXattr(c *models.Collection) error {
	c.Mutex().Lock()
	defer c.Mutex().Unlock()

	data, err := json.Marshal(c)
	if err != nil {
		utils.LogErrOnce("", fmt.Errorf("xattr: %s %s", c.Path, err))
		return err
	}

	f, err := os.OpenFile(c.Path, os.O_WRONLY, 0)
	if err != nil {
		utils.LogErrOnce("", fmt.Errorf("xattr: %s %s", c.Path, err))
		return err
	}
	defer f.Close()

	err = unix.Fsetxattr(int(f.Fd()), models.XattrName, data, 0)
	if err != nil {
		utils.LogErrOnce("", fmt.Errorf("xattr: %s %s", c.Path, err))
		return err
	}
	return nil
}

func (s *Storage) Exists(filename string) bool {
	path := filepath.Join(s.artifacts, filename)
	_, err := os.Stat(path)
	return err == nil
}
