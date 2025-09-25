// (c) Matt Martz <matt@sivel.net>
// GNU General Public License v3.0+
//     (see https://www.gnu.org/licenses/gpl-3.0.txt)

package main

import (
	_ "embed"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/gin-contrib/location"
	"github.com/gin-gonic/gin"

	"github.com/sivel/amanda/handlers"
	"github.com/sivel/amanda/storage"
	"github.com/sivel/amanda/utils"
)

//go:embed index.html
var indexHTML []byte

var (
	gitSHA    = "unknown"
	buildDate = "unknown"
	goVersion = "unknown"
)

func printVersion() {
	fmt.Printf("Git SHA:    %s\n", gitSHA)
	fmt.Printf("Build Date: %s\n", buildDate)
	fmt.Printf("Go Version: %s\n", goVersion)
}

func main() {
	var artifacts string
	var port string
	var relative bool
	var ui bool
	var xattrs bool
	var publish bool
	var version bool
	var err error

	flag.StringVar(&artifacts, "artifacts", "artifacts", "Location of the artifacts dir")
	flag.StringVar(&port, "port", "5000", "Port")
	flag.BoolVar(&relative, "relative", false, "URLs will not include the scheme and domain")
	flag.BoolVar(&ui, "ui", false, "Enable the HTML UI")
	flag.BoolVar(&xattrs, "xattrs", false, "Enable caching metadata on xattrs for faster startup")
	flag.BoolVar(&publish, "publish", false, "Enable publishing routes")
	flag.BoolVar(&version, "V", false, "Print version information and exit")
	flag.Parse()

	printVersion()
	if version {
		return
	}

	log.SetOutput(gin.DefaultErrorWriter)

	artifacts, err = filepath.Abs(artifacts)
	if err != nil {
		log.Fatal(err)
	}

	amanda := handlers.New(relative, storage.New(artifacts, xattrs))

	r := gin.Default()
	r.MaxMultipartMemory = 20 << 20
	r.RedirectTrailingSlash = true

	r.Use(location.Default())
	r.Use(utils.LogStatusContext())

	r.GET("/api/", amanda.Api)
	r.GET("/api/v3/collections/", amanda.Collections)
	r.GET("/api/v3/collections/:namespace/:name/", amanda.Collection)
	r.GET("/api/v3/collections/:namespace/:name/versions/", amanda.Versions)
	r.GET("/api/v3/collections/:namespace/:name/versions/:version/", amanda.Version)
	r.Static("/artifacts", artifacts)

	if publish {
		r.POST("/api/v3/artifacts/collections/", amanda.Publish)
		r.GET("/api/v3/imports/collections/:task/", amanda.ImportTask)
	}

	if ui {
		if _, err := os.Stat("./index.html"); err != nil || gin.Mode() == gin.ReleaseMode {
			r.GET("/", amanda.IndexHTML(indexHTML))
			r.GET("/index.html", amanda.IndexHTML(indexHTML))
		} else {
			r.StaticFile("/", "./index.html")
			r.StaticFile("/index.html", "./index.html")
		}
		r.GET("/_ui/v1/docs/:namespace/:name/versions/:version/", amanda.Docs)
	}

	r.Run(":" + port)
}
