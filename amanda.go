// (c) Matt Martz <matt@sivel.net>
// GNU General Public License v3.0+
//     (see https://www.gnu.org/licenses/gpl-3.0.txt)

package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	semver "github.com/Masterminds/semver/v3"
	"github.com/gin-contrib/location"
	"github.com/gin-gonic/gin"
	"golang.org/x/sys/unix"
	yaml "gopkg.in/yaml.v3"
)

const xattrName = "user.amanda"
const iso8601 = "2006-01-02T15:04:05.000000-0700"

//go:embed index.html
var embeddedFiles embed.FS

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

type CollectionRuntime struct {
	RequiresAnsible string `json:"requires_ansible" yaml:"requires_ansible"`
}

type Collection struct {
	Filename        string
	Path            string
	Sha             string
	Created         string         `json:"created"`
	CollectionInfo  CollectionInfo `json:"collection_info"`
	Signatures      []CollectionSignature
	RequiresAnsible string `json:"requires_ansible"`
	xattrMutex      sync.Mutex
}

func (c *Collection) Matches(namespace string, name string, version string) bool {
	match := true
	if namespace != "" && name != "" {
		match = c.CollectionInfo.Namespace == namespace && c.CollectionInfo.Name == name
	}

	if match && version != "" {
		constraint, _ := semver.NewConstraint(fmt.Sprintf("= %s", version))
		match = match && constraint.Check(c.CollectionInfo.Version)
	}

	return match
}

func (c *Collection) WriteXattr() error {
	c.xattrMutex.Lock()
	defer c.xattrMutex.Unlock()

	data, err := json.Marshal(c)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(c.Path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	return unix.Fsetxattr(int(f.Fd()), xattrName, data, 0)
}

func collectionFromXattr(path string, xattrs bool) (*Collection, error) {
	if !xattrs {
		return nil, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	size, err := unix.Fgetxattr(int(f.Fd()), xattrName, nil)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, size)
	_, err = unix.Fgetxattr(int(f.Fd()), xattrName, buf)
	if err != nil {
		return nil, err
	}

	var collection Collection
	if err := json.Unmarshal(buf, &collection); err != nil {
		return nil, err
	}

	createdTime, err := time.Parse(iso8601, collection.Created)
	if err != nil {
		return nil, err
	}

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	modTime := info.ModTime().Truncate(time.Microsecond)

	if !modTime.Equal(createdTime) {
		unix.Fremovexattr(int(f.Fd()), xattrName)
		return nil, fmt.Errorf("modtime mismatch")
	}

	return &collection, nil
}

func getSha256Digest(file *os.File) (string, error) {
	defer file.Seek(0, 0)
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func getManifest(file *os.File) (*Collection, error) {
	defer file.Seek(0, 0)

	var collection Collection

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return &collection, err
	}
	tarReader := tar.NewReader(gzReader)
	for {
		header, err := tarReader.Next()

		if err == io.EOF {
			break
		}

		if err != nil {
			return &collection, err
		}

		name := strings.ToLower(header.Name)

		if name == "manifest.json" || name == "./manifest.json" {
			data := make([]byte, header.Size)
			_, err := tarReader.Read(data)
			if err != io.EOF && err != nil {
				continue
			}
			err = json.Unmarshal(data, &collection)
			if err != nil {
				return &collection, err
			}
			break
		}
	}
	return &collection, nil
}

func getRuntime(file *os.File) (*CollectionRuntime, error) {
	defer file.Seek(0, 0)

	var runtime CollectionRuntime

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return &runtime, err
	}
	tarReader := tar.NewReader(gzReader)
	for {
		header, err := tarReader.Next()

		if err == io.EOF {
			break
		}

		if err != nil {
			return &runtime, err
		}

		name := strings.ToLower(header.Name)

		if name == "meta/runtime.yml" || name == "./meta/runtime.yml" {
			data := make([]byte, header.Size)
			_, err := tarReader.Read(data)
			if err != io.EOF && err != nil {
				continue
			}
			err = yaml.Unmarshal(data, &runtime)
			if err != nil {
				return &runtime, err
			}
			break
		}
	}
	return &runtime, nil
}

func collectionFromTar(path string) (*Collection, error) {
	var collection *Collection

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	collection, err = getManifest(file)
	if err != nil {
		return nil, err
	}
	collection.Sha, err = getSha256Digest(file)
	if err != nil {
		return nil, err
	}

	runtime, err := getRuntime(file)
	if err == nil {
		collection.RequiresAnsible = runtime.RequiresAnsible
	}

	return collection, nil
}

type discoveryCacheKey struct {
	filename string
	modtime  time.Time
}

type Discover struct {
	artifacts string
	xattrs    bool
	cache     sync.Map
}

func (d *Discover) cacheKey(filename string, modtime time.Time) discoveryCacheKey {
	return discoveryCacheKey{filename, modtime}
}

func (d *Discover) store(filename string, modtime time.Time, collection *Collection) {
	key := d.cacheKey(filename, modtime)
	d.cache.Store(key, collection)
}

func (d *Discover) load(filename string, modtime time.Time) (*Collection, bool) {
	key := d.cacheKey(filename, modtime)
	val, ok := d.cache.Load(key)
	if ok {
		return val.(*Collection), ok
	}
	return nil, ok
}

func (d *Discover) Get(namespace string, name string, version string) ([]*Collection, error) {
	var collections []*Collection

	files, err := os.ReadDir(d.artifacts)
	if err != nil {
		return collections, err
	}

	for _, entry := range files {
		fileInfo, err := entry.Info()
		if err != nil {
			continue
		}

		var collection *Collection
		filename := fileInfo.Name()
		path := filepath.Join(d.artifacts, filename)
		extension := filename[len(filename)-7:]
		if extension != ".tar.gz" {
			continue
		}
		stem := filename[:len(filename)-7]
		signatureFilename := stem + ".asc"
		modtime := fileInfo.ModTime()
		if val, ok := d.load(filename, modtime); ok {
			collection = val
		} else if val, err := collectionFromXattr(path, d.xattrs); val != nil {
			collection = val
			collection.Filename = filename
			collection.Path = path
			d.store(filename, modtime, collection)
		} else {
			collection, err = collectionFromTar(path)
			if err != nil {
				continue
			}

			collection.Filename = filename
			collection.Path = path
			collection.Created = modtime.Format(iso8601)

			signature, err := os.ReadFile(filepath.Join(d.artifacts, signatureFilename))
			if err == nil {
				collectionSignature := CollectionSignature{string(signature)}
				collection.Signatures = append(collection.Signatures, collectionSignature)
			}
			d.store(filename, modtime, collection)
			if d.xattrs {
				collection.WriteXattr()
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

type Amanda struct {
	relative bool
	discover *Discover
}

func (a *Amanda) getHost(c *gin.Context) string {
	if a.relative {
		return ""
	}
	url := location.Get(c)
	return fmt.Sprintf("%s://%s", url.Scheme, c.Request.Host)
}

func (a *Amanda) NotFound(c *gin.Context) {
	c.JSON(http.StatusNotFound, NotFound)
}

func (a *Amanda) IndexHTML(c *gin.Context) {
	content, err := embeddedFiles.ReadFile("index.html")
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", content)
}

func (a *Amanda) Api(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"available_versions": gin.H{
			"v3": "v3/",
		},
		"description": "Amanda Galaxy REST API",
	})
}

func (a *Amanda) Collections(c *gin.Context) {
	discovered, err := a.discover.Get("", "", "")
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	var results []gin.H
	collections := make(map[string][]*Collection)

	for _, collection := range discovered {
		namespace := collection.CollectionInfo.Namespace
		name := collection.CollectionInfo.Name
		seenKey := namespace + "." + name

		if _, ok := collections[seenKey]; !ok {
			collections[seenKey] = make([]*Collection, 0)
		}

		collections[seenKey] = append(collections[seenKey], collection)
		continue
	}

	for _, versions := range collections {
		var prodVersions []*Collection
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
			"versions_url": fmt.Sprintf("%s/api/v3/collections/%s/%s/versions/", a.getHost(c), namespace, name),
		}

		var latestVersion string
		if len(prodVersions) > 0 {
			latestProd := prodVersions[len(prodVersions)-1]
			latestVersion = latestProd.CollectionInfo.Version.String()
		} else {
			latestVersion = latest.CollectionInfo.Version.String()
		}
		result["highest_version"] = gin.H{
			"href":    fmt.Sprintf("%s/api/v3/collections/%s/%s/versions/%s/", a.getHost(c), namespace, name, latestVersion),
			"version": latestVersion,
		}
		results = append(results, result)
	}

	out := gin.H{
		"results": results,
	}

	c.JSON(http.StatusOK, out)
}

func (a *Amanda) Collection(c *gin.Context) {
	namespace := c.Params.ByName("namespace")
	name := c.Params.ByName("name")
	discovered, err := a.discover.Get(namespace, name, "")
	var prodCollections []*Collection

	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
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
		"versions_url": fmt.Sprintf("%s/api/v3/collections/%s/%s/versions/", a.getHost(c), namespace, name),
		"href":         fmt.Sprintf("%s/api/v3/collections/%s/%s/", a.getHost(c), namespace, name),
	}

	var latestVersion string
	if len(prodCollections) > 0 {
		latestProd := prodCollections[len(prodCollections)-1]
		latestVersion = latestProd.CollectionInfo.Version.String()
	} else {
		latestVersion = latest.CollectionInfo.Version.String()
	}
	out["highest_version"] = gin.H{
		"href":    fmt.Sprintf("%s/api/v3/collections/%s/%s/versions/%s/", a.getHost(c), namespace, name, latestVersion),
		"version": latestVersion,
	}

	c.JSON(http.StatusOK, out)
}

func (a *Amanda) Versions(c *gin.Context) {
	namespace := c.Params.ByName("namespace")
	name := c.Params.ByName("name")
	discovered, err := a.discover.Get(namespace, name, "")
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	if len(discovered) == 0 {
		a.NotFound(c)
		return
	}

	sort.Slice(discovered, func(i, j int) bool {
		return discovered[i].CollectionInfo.Version.GreaterThan(discovered[j].CollectionInfo.Version)
	})

	var versions []gin.H
	for _, collection := range discovered {
		versions = append(
			versions,
			gin.H{
				"href":    fmt.Sprintf("%s/api/v3/collections/%s/%s/versions/%s/", a.getHost(c), namespace, name, collection.CollectionInfo.Version.String()),
				"version": collection.CollectionInfo.Version.String(),
			},
		)
	}
	c.JSON(http.StatusOK, gin.H{
		"results": versions,
	})
}

func (a *Amanda) Version(c *gin.Context) {
	namespace := c.Params.ByName("namespace")
	name := c.Params.ByName("name")
	version := c.Params.ByName("version")
	discovered, err := a.discover.Get(namespace, name, version)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	if len(discovered) == 0 {
		a.NotFound(c)
		return
	}
	collection := discovered[0]

	c.JSON(http.StatusOK, gin.H{
		"artifact": gin.H{
			"filename": collection.Filename,
			"sha256":   collection.Sha,
		},
		"collection": gin.H{
			"name": name,
			"href": fmt.Sprintf("%s/api/v3/collections/%s/%s/", a.getHost(c), namespace, name),
		},
		"name": name,
		"namespace": gin.H{
			"name": namespace,
		},
		"download_url":     fmt.Sprintf("%s/artifacts/%s", a.getHost(c), collection.Filename),
		"metadata":         collection.CollectionInfo,
		"version":          version,
		"signatures":       collection.Signatures,
		"href":             fmt.Sprintf("%s/api/v3/collections/%s/%s/versions/%s/", a.getHost(c), namespace, name, version),
		"requires_ansible": collection.RequiresAnsible,
	})
}

func main() {
	var artifacts string
	var port string
	var relative bool
	var ui bool
	var xattrs bool
	var err error

	flag.StringVar(&artifacts, "artifacts", "artifacts", "Location of the artifacts dir")
	flag.StringVar(&port, "port", "5000", "Port")
	flag.BoolVar(&relative, "relative", false, "URLs will not include the scheme and domain")
	flag.BoolVar(&ui, "ui", false, "Enable the HTML UI")
	flag.BoolVar(&xattrs, "xattrs", false, "Enable caching metadata on xattrs for faster startup")
	flag.Parse()

	log.SetOutput(gin.DefaultErrorWriter)

	artifacts, err = filepath.Abs(artifacts)
	if err != nil {
		log.Fatal(err)
	}

	discover := &Discover{
		artifacts: artifacts,
		xattrs:    xattrs,
	}
	amanda := Amanda{
		relative: relative,
		discover: discover,
	}

	r := gin.Default()
	r.RedirectTrailingSlash = true
	r.Use(location.Default())
	if ui {
		if _, err := os.Stat("./index.html"); err != nil || gin.Mode() == gin.ReleaseMode {
			r.GET("/", amanda.IndexHTML)
			r.GET("/index.html", amanda.IndexHTML)
		} else {
			r.StaticFile("/", "./index.html")
			r.StaticFile("/index.html", "./index.html")
		}
	}
	r.GET("/api/", amanda.Api)
	r.GET("/api/v3/collections/", amanda.Collections)
	r.GET("/api/v3/collections/:namespace/:name/", amanda.Collection)
	r.GET("/api/v3/collections/:namespace/:name/versions/", amanda.Versions)
	r.GET("/api/v3/collections/:namespace/:name/versions/:version/", amanda.Version)
	r.Static("/artifacts", artifacts)
	r.Run(":" + port)
}
