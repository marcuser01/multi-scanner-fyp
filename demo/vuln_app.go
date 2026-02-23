package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os/exec"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	// CWE-78: OS Command Injection
	r.GET("/ping", func(c *gin.Context) {
		host := c.Query("host")
		// Directly passing user input to a shell command
		out, err := exec.Command("ping", "-c", "1", host).Output()
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()}) // CWE-209: Error Message Exposure
			return
		}
		c.String(200, string(out))
	})

	// CWE-295: Improper Certificate Validation
	r.GET("/fetch-internal", func(c *gin.Context) {
		tr := &http.Transport{
			// InsecureSkipVerify: true disables TLS checks entirely
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
		resp, _ := client.Get("https://internal-service.local/data")
		c.DataFromReader(200, resp.ContentLength, "application/json", resp.Body, nil)
	})

	r.Run(":8080")
}
