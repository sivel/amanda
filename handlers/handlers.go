// (c) Matt Martz <matt@sivel.net>
// GNU General Public License v3.0+
//     (see https://www.gnu.org/licenses/gpl-3.0.txt)

package handlers

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/gin-contrib/location"
	"github.com/gin-gonic/gin"

	"github.com/sivel/amanda/models"
	"github.com/sivel/amanda/storage"
	"github.com/sivel/amanda/utils"
)

var NotFound = gin.H{
	"code":    "not_found",
	"message": "Not found.",
}

type Amanda struct {
	relative     bool
	storage      *storage.Storage
	publishMutex sync.Mutex
}

func New(relative bool, storage *storage.Storage) *Amanda {
	return &Amanda{
		relative: relative,
		storage:  storage,
	}
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

func (a *Amanda) IndexHTML(content []byte) func(c *gin.Context) {
	return func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", content)
	}
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
	discovered, err := a.storage.Read("", "", "")
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	collections := make(map[string][]*models.Collection)
	for _, collection := range discovered {
		namespace := collection.CollectionInfo.Namespace
		name := collection.CollectionInfo.Name
		seenKey := namespace + "." + name

		if _, ok := collections[seenKey]; !ok {
			collections[seenKey] = make([]*models.Collection, 0)
		}

		collections[seenKey] = append(collections[seenKey], collection)
	}

	var results []gin.H
	for _, versions := range collections {
		results = append(results, a.buildCollectionResponse(c, versions))
	}

	if results == nil {
		results = make([]gin.H, 0)
	}

	c.JSON(http.StatusOK, gin.H{
		"results": results,
	})
}

func (a *Amanda) buildCollectionResponse(c *gin.Context, versions []*models.Collection) gin.H {
	prodVersions := a.filterProdVersions(versions)
	a.sortVersions(versions)
	a.sortVersions(prodVersions)

	latest := versions[0]
	oldest := versions[len(versions)-1]
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

	latestVersion := a.getLatestVersion(prodVersions, versions)
	result["highest_version"] = gin.H{
		"href":    fmt.Sprintf("%s/api/v3/collections/%s/%s/versions/%s/", a.getHost(c), namespace, name, latestVersion),
		"version": latestVersion,
	}

	return result
}

func (a *Amanda) filterProdVersions(versions []*models.Collection) []*models.Collection {
	var prodVersions []*models.Collection
	for _, version := range versions {
		if version.CollectionInfo.Version.Prerelease() == "" {
			prodVersions = append(prodVersions, version)
		}
	}
	return prodVersions
}

func (a *Amanda) sortVersions(versions []*models.Collection) {
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].CollectionInfo.Version.GreaterThan(versions[j].CollectionInfo.Version)
	})
}

func (a *Amanda) getLatestVersion(prodVersions, allVersions []*models.Collection) string {
	if len(prodVersions) > 0 {
		return prodVersions[0].CollectionInfo.Version.String()
	}
	return allVersions[0].CollectionInfo.Version.String()
}

func (a *Amanda) Collection(c *gin.Context) {
	namespace := c.Params.ByName("namespace")
	name := c.Params.ByName("name")
	discovered, err := a.storage.Read(namespace, name, "")
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	if len(discovered) == 0 {
		a.NotFound(c)
		return
	}

	prodCollections := a.filterProdVersions(discovered)
	a.sortVersions(discovered)
	a.sortVersions(prodCollections)

	latest := discovered[0]
	oldest := discovered[len(discovered)-1]

	out := gin.H{
		"name":         name,
		"namespace":    namespace,
		"updated_at":   latest.Created,
		"created_at":   oldest.Created,
		"versions_url": fmt.Sprintf("%s/api/v3/collections/%s/%s/versions/", a.getHost(c), namespace, name),
		"href":         fmt.Sprintf("%s/api/v3/collections/%s/%s/", a.getHost(c), namespace, name),
	}

	latestVersion := a.getLatestVersion(prodCollections, discovered)
	out["highest_version"] = gin.H{
		"href":    fmt.Sprintf("%s/api/v3/collections/%s/%s/versions/%s/", a.getHost(c), namespace, name, latestVersion),
		"version": latestVersion,
	}
	c.JSON(http.StatusOK, out)
}

func (a *Amanda) Versions(c *gin.Context) {
	namespace := c.Params.ByName("namespace")
	name := c.Params.ByName("name")
	discovered, err := a.storage.Read(namespace, name, "")
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	if len(discovered) == 0 {
		a.NotFound(c)
		return
	}

	a.sortVersions(discovered)

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
	discovered, err := a.storage.Read(namespace, name, version)
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
		"signatures":       a.storage.ReadSignatures(collection.Path),
		"href":             fmt.Sprintf("%s/api/v3/collections/%s/%s/versions/%s/", a.getHost(c), namespace, name, version),
		"requires_ansible": collection.RequiresAnsible,
	})
}

func (a *Amanda) Publish(c *gin.Context) {
	a.publishMutex.Lock()
	defer a.publishMutex.Unlock()

	sha256 := c.PostForm("sha256")
	if sha256 == "" {
		c.String(http.StatusBadRequest, "publish error: missing sha256")
		return
	}

	file, err := c.FormFile("file")
	if err != nil {
		c.String(http.StatusBadRequest, "publish error: %s", err.Error())
		return
	}

	srcBuf, err := utils.PrepareFormFile(file)
	if err != nil {
		c.String(http.StatusBadRequest, "publish error: %s", err.Error())
		return
	}

	dst, err := a.storage.Write(sha256, file.Filename, srcBuf)
	if err != nil {
		c.String(http.StatusBadRequest, "publish error: %s", err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"task": fmt.Sprintf("%s/api/v3/imports/collections/%s/", a.getHost(c), dst),
	})
}

func (a *Amanda) ImportTask(c *gin.Context) {
	dstName := c.Params.ByName("task")
	if !a.storage.Exists(dstName) {
		a.NotFound(c)
	}
	c.JSON(http.StatusOK, gin.H{
		"state":       "completed",
		"finished_at": time.Now().Format(models.ISO8601),
	})
}
