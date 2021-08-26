// (c) 2021 Matt Martz <matt@sivel.net>
// GNU General Public License v3.0+
//     (see https://www.gnu.org/licenses/gpl-3.0.txt)

package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Masterminds/semver"
	"github.com/gin-contrib/location"
	"github.com/gin-gonic/gin"
)

var NotFound = gin.H{
	"code":    "not_found",
	"message": "Not found.",
}

type CollectionInfo struct {
	Namespace    string          `json:"namespace"`
	Name         string          `json:"name"`
	Version      *semver.Version `json:"version"`
	Dependencies gin.H           `json:"dependencies"`
}

type Collection struct {
	Filename       string
	Path           string
	Sha            string
	Created        string         `json:"created"`
	CollectionInfo CollectionInfo `json:"collection_info"`
}

var discoveryCache = make(map[string]map[time.Time]Collection)

func (c *Collection) Matches(namespace string, name string, version string) bool {
	var match bool = true
	if namespace != "" && name != "" {
		match = c.CollectionInfo.Namespace == namespace && c.CollectionInfo.Name == name
	}

	if match && version != "" {
		constraint, _ := semver.NewConstraint(fmt.Sprintf("= %s", version))
		match = match && constraint.Check(c.CollectionInfo.Version)
	}

	return match
}

func getSha256Digest(file *os.File) (string, error) {
	defer file.Seek(0, 0)
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func getManifest(file *os.File) (Collection, error) {
	defer file.Seek(0, 0)

	var collection Collection

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return collection, err
	}
	tarReader := tar.NewReader(gzReader)
	for {
		header, err := tarReader.Next()

		if err == io.EOF {
			break
		}

		if err != nil {
			return collection, err
		}

		if strings.ToLower(header.Name) == "manifest.json" {
			data := make([]byte, header.Size)
			_, err := tarReader.Read(data)
			if err != io.EOF && err != nil {
				continue
			}
			json.Unmarshal(data, &collection)
			break
		}
	}
	return collection, nil
}

func discoverCollections(artifacts string, namespace string, name string, version string) ([]Collection, error) {
	var collections []Collection

	files, err := ioutil.ReadDir(artifacts)
	if err != nil {
		return collections, err
	}

	for _, fileInfo := range files {
		var collection Collection
		var shaErr error
		filename := fileInfo.Name()
		if val, ok := discoveryCache[filename][fileInfo.ModTime()]; ok {
			collection = val
		} else {
			path := filepath.Join(artifacts, filename)
			file, err := os.Open(path)
			if err != nil {
				continue
			}
			collection, err = getManifest(file)
			if err != nil {
				continue
			}
			collection.Filename = filename
			collection.Path = path
			collection.Created = fileInfo.ModTime().Format("2006-01-02T15:04:05.000000-0700")
			collection.Sha, shaErr = getSha256Digest(file)
			file.Close()
			if shaErr != nil {
				continue
			}
			if _, ok := discoveryCache[filename]; !ok {
				discoveryCache[filename] = make(map[time.Time]Collection)
			}
			discoveryCache[filename][fileInfo.ModTime()] = collection
		}

		if collection.Matches(namespace, name, version) {
			collections = append(collections, collection)
			if version != "" {
				break
			}
		}
	}

	return collections, nil
}

func getHost(c *gin.Context) string {
	url := location.Get(c)
	return fmt.Sprintf("%s://%s", url.Scheme, c.Request.Host)
}

type Amanda struct {
	Artifacts string
}

func (a *Amanda) NotFound(c *gin.Context) {
	c.JSON(404, NotFound)
}

func (a *Amanda) Api(c *gin.Context) {
	c.JSON(200, gin.H{
		"available_versions": gin.H{
			"v2": "v2/",
		},
		"current_version": "v1",
		"description":     "AMANDA GALAXY REST API",
	})
}

func (a *Amanda) Collection(c *gin.Context) {
	namespace := c.Params.ByName("namespace")
	name := c.Params.ByName("name")
	collections, err := discoverCollections(a.Artifacts, namespace, name, "")
	var prodCollections []Collection

	if err != nil {
		c.AbortWithError(500, err)
		return
	}
	if len(collections) == 0 {
		a.NotFound(c)
		return
	}

	for _, collection := range collections {
		if collection.CollectionInfo.Version.Prerelease() == "" {
			prodCollections = append(prodCollections, collection)
		}
	}

	sort.Slice(collections, func(i, j int) bool {
		return collections[i].CollectionInfo.Version.LessThan(collections[j].CollectionInfo.Version)
	})

	sort.Slice(prodCollections, func(i, j int) bool {
		return prodCollections[i].CollectionInfo.Version.LessThan(prodCollections[j].CollectionInfo.Version)
	})

	latest := collections[len(collections)-1]
	oldest := collections[0]
	out := gin.H{
		"name": name,
		"namespace": gin.H{
			"name": namespace,
		},
		"modified":     latest.Created,
		"created":      oldest.Created,
		"versions_url": fmt.Sprintf("%s/api/v2/collections/%s/%s/versions/", getHost(c), namespace, name),
	}

	if len(prodCollections) > 0 {
		latestProd := prodCollections[len(prodCollections)-1]
		version := latestProd.CollectionInfo.Version.String()
		out["latest_version"] = gin.H{
			"href":    fmt.Sprintf("%s/api/v2/collections/%s/%s/versions/%s/", getHost(c), namespace, name, version),
			"version": version,
		}
	}

	c.JSON(200, out)
}

func (a *Amanda) Versions(c *gin.Context) {
	namespace := c.Params.ByName("namespace")
	name := c.Params.ByName("name")
	collections, err := discoverCollections(a.Artifacts, namespace, name, "")
	if err != nil {
		c.AbortWithError(500, err)
		return
	}
	if len(collections) == 0 {
		a.NotFound(c)
		return
	}

	var versions []gin.H
	for _, collection := range collections {
		versions = append(
			versions,
			gin.H{
				"href":    fmt.Sprintf("%s/api/v2/collections/%s/%s/versions/%s/", getHost(c), namespace, name, collection.CollectionInfo.Version.String()),
				"version": collection.CollectionInfo.Version.String(),
			},
		)
	}
	c.JSON(200, gin.H{
		"results": versions,
	})
}

func (a *Amanda) Version(c *gin.Context) {
	namespace := c.Params.ByName("namespace")
	name := c.Params.ByName("name")
	version := c.Params.ByName("version")
	collections, err := discoverCollections(a.Artifacts, namespace, name, version)
	if err != nil {
		c.AbortWithError(500, err)
		return
	}
	if len(collections) == 0 {
		a.NotFound(c)
		return
	}
	collection := collections[0]

	c.JSON(200, gin.H{
		"artifact": gin.H{
			"filename": collection.Filename,
			"sha256":   collection.Sha,
		},
		"collection": gin.H{
			"name": name,
		},
		"namespace": gin.H{
			"name": namespace,
		},
		"download_url": fmt.Sprintf("%s/artifacts/%s", getHost(c), collection.Filename),
		"metadata":     collection.CollectionInfo,
		"version":      version,
	})
}

func main() {
	var artifacts string
	var port string
	var err error
	amanda := Amanda{}

	flag.StringVar(&artifacts, "artifacts", "artifacts", "Location of the artifacts dir")
	flag.StringVar(&port, "port", "5000", "Port")
	flag.Parse()

	amanda.Artifacts, err = filepath.Abs(artifacts)
	if err != nil {
		log.Fatal(err)
	}

	r := gin.Default()
	r.RedirectTrailingSlash = true
	r.Use(location.Default())
	r.GET("/api/", amanda.Api)
	r.GET("/api/v2/collections/:namespace/:name/", amanda.Collection)
	r.GET("/api/v2/collections/:namespace/:name/versions/", amanda.Versions)
	r.GET("/api/v2/collections/:namespace/:name/versions/:version/", amanda.Version)
	r.Static("/artifacts", amanda.Artifacts)
	r.Run(":" + port)
}
