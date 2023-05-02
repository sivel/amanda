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

	"github.com/Masterminds/semver/v3"
	"github.com/gin-contrib/location"
	"github.com/gin-gonic/gin"
)

var NotFound = gin.H{
	"code":    "not_found",
	"message": "Not found.",
}

type CollectionSignature struct {
	Signature string `json:"signature"`
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
	Signatures     []CollectionSignature
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

		if strings.ToLower(header.Name) == "manifest.json" || strings.ToLower(header.Name) == "./manifest.json" {
			data := make([]byte, header.Size)
			_, err := tarReader.Read(data)
			if err != io.EOF && err != nil {
				continue
			}
			err = json.Unmarshal(data, &collection)
			if err != nil {
				return collection, err
			}
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
		extension := filename[len(filename)-7:]
		if extension != ".tar.gz" {
			continue
		}
		stem := filename[:len(filename)-7]
		signatureFilename := stem + ".asc"
		modtime := fileInfo.ModTime()
		if val, ok := discoveryCache[filename][modtime]; ok {
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
			collection.Sha, shaErr = getSha256Digest(file)
			file.Close()
			if shaErr != nil {
				continue
			}
			collection.Filename = filename
			collection.Path = path
			collection.Created = modtime.Format("2006-01-02T15:04:05.000000-0700")
			signature, err := os.ReadFile(filepath.Join(artifacts, signatureFilename))
			if err == nil {
				collectionSignature := CollectionSignature{string(signature)}
				collection.Signatures = append(collection.Signatures, collectionSignature)
			}
			if _, ok := discoveryCache[filename]; !ok {
				discoveryCache[filename] = make(map[time.Time]Collection)
			}
			discoveryCache[filename][modtime] = collection
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
			"v3": "v3/",
		},
		"description": "Amanda Galaxy REST API",
	})
}

func (a *Amanda) Collections(c *gin.Context) {
	discovered, err := discoverCollections(a.Artifacts, "", "", "")
	if err != nil {
		c.AbortWithError(500, err)
		return
	}

	var results []gin.H
	collections := make(map[string][]Collection)

	for _, collection := range discovered {
		namespace := collection.CollectionInfo.Namespace
		name := collection.CollectionInfo.Name
		seenKey := namespace + "." + name

		if _, ok := collections[seenKey]; !ok {
			collections[seenKey] = make([]Collection, 0)
		}

		collections[seenKey] = append(collections[seenKey], collection)
		continue
	}

	for _, versions := range collections {
		var prodVersions []Collection
		for _, version := range versions {
			if version.CollectionInfo.Version.Prerelease() == "" {
				prodVersions = append(prodVersions, version)
			}
		}

		sort.Slice(versions, func(i, j int) bool {
			return versions[i].CollectionInfo.Version.LessThan(versions[j].CollectionInfo.Version)
		})

		sort.Slice(prodVersions, func(i, j int) bool {
			return prodVersions[i].CollectionInfo.Version.LessThan(prodVersions[j].CollectionInfo.Version)
		})

		latest := versions[len(versions)-1]
		oldest := versions[0]

		namespace := latest.CollectionInfo.Namespace
		name := latest.CollectionInfo.Name

		result := gin.H{
			"name": name,
			"namespace": gin.H{
				"name": namespace,
			},
			"updated_at":   latest.Created,
			"created_at":   oldest.Created,
			"versions_url": fmt.Sprintf("%s/api/v3/collections/%s/%s/versions/", getHost(c), namespace, name),
		}

		if len(prodVersions) > 0 {
			latestProd := prodVersions[len(prodVersions)-1]
			latestVersion := latestProd.CollectionInfo.Version.String()
			result["highest_version"] = gin.H{
				"href":    fmt.Sprintf("%s/api/v3/collections/%s/%s/versions/%s/", getHost(c), namespace, name, latestVersion),
				"version": latestVersion,
			}
		}
		results = append(results, result)
	}

	out := gin.H{
		"results": results,
	}

	c.JSON(200, out)
}

func (a *Amanda) Collection(c *gin.Context) {
	namespace := c.Params.ByName("namespace")
	name := c.Params.ByName("name")
	discovered, err := discoverCollections(a.Artifacts, namespace, name, "")
	var prodCollections []Collection

	if err != nil {
		c.AbortWithError(500, err)
		return
	}
	if len(discovered) == 0 {
		a.NotFound(c)
		return
	}

	for _, collection := range discovered {
		if collection.CollectionInfo.Version.Prerelease() == "" {
			prodCollections = append(prodCollections, collection)
		}
	}

	sort.Slice(discovered, func(i, j int) bool {
		return discovered[i].CollectionInfo.Version.LessThan(discovered[j].CollectionInfo.Version)
	})

	sort.Slice(prodCollections, func(i, j int) bool {
		return prodCollections[i].CollectionInfo.Version.LessThan(prodCollections[j].CollectionInfo.Version)
	})

	latest := discovered[len(discovered)-1]
	oldest := discovered[0]
	out := gin.H{
		"name":         name,
		"namespace":    namespace,
		"updated_at":   latest.Created,
		"created_at":   oldest.Created,
		"versions_url": fmt.Sprintf("%s/api/v3/collections/%s/%s/versions/", getHost(c), namespace, name),
		"href":         fmt.Sprintf("%s/api/v3/collections/%s/%s/", getHost(c), namespace, name),
	}

	if len(prodCollections) > 0 {
		latestProd := prodCollections[len(prodCollections)-1]
		version := latestProd.CollectionInfo.Version.String()
		out["highest_version"] = gin.H{
			"href":    fmt.Sprintf("%s/api/v3/collections/%s/%s/versions/%s/", getHost(c), namespace, name, version),
			"version": version,
		}
	}

	c.JSON(200, out)
}

func (a *Amanda) Versions(c *gin.Context) {
	namespace := c.Params.ByName("namespace")
	name := c.Params.ByName("name")
	discovered, err := discoverCollections(a.Artifacts, namespace, name, "")
	if err != nil {
		c.AbortWithError(500, err)
		return
	}
	if len(discovered) == 0 {
		a.NotFound(c)
		return
	}

	var versions []gin.H
	for _, collection := range discovered {
		versions = append(
			versions,
			gin.H{
				"href":    fmt.Sprintf("%s/api/v3/collections/%s/%s/versions/%s/", getHost(c), namespace, name, collection.CollectionInfo.Version.String()),
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
	discovered, err := discoverCollections(a.Artifacts, namespace, name, version)
	if err != nil {
		c.AbortWithError(500, err)
		return
	}
	if len(discovered) == 0 {
		a.NotFound(c)
		return
	}
	collection := discovered[0]

	c.JSON(200, gin.H{
		"artifact": gin.H{
			"filename": collection.Filename,
			"sha256":   collection.Sha,
		},
		"collection": gin.H{
			"name": name,
			"href": fmt.Sprintf("%s/api/v3/collections/%s/%s/", getHost(c), namespace, name),
		},
		"name": name,
		"namespace": gin.H{
			"name": namespace,
		},
		"download_url": fmt.Sprintf("%s/artifacts/%s", getHost(c), collection.Filename),
		"metadata":     collection.CollectionInfo,
		"version":      version,
		"signatures":   collection.Signatures,
		"href":         fmt.Sprintf("%s/api/v3/collections/%s/%s/versions/%s/", getHost(c), namespace, name, version),
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
	r.GET("/api/v3/collections/", amanda.Collections)
	r.GET("/api/v3/collections/:namespace/:name/", amanda.Collection)
	r.GET("/api/v3/collections/:namespace/:name/versions/", amanda.Versions)
	r.GET("/api/v3/collections/:namespace/:name/versions/:version/", amanda.Version)
	r.Static("/artifacts", amanda.Artifacts)
	r.Run(":" + port)
}
