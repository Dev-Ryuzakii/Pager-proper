package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

var headwindServerURL = os.Getenv("HEADWIND_SERVER_URL")
var headwindAPIKey = os.Getenv("HEADWIND_API_KEY")
var connectorToken = os.Getenv("MDM_CONNECTOR_TOKEN")

// EnrollRequest represents the JSON payload to enroll a device.
type EnrollRequest struct {
	DeviceID string `json:"device_id"`
	IMEI     string `json:"imei"`
	UserID   int    `json:"user_id"`
}

func main() {
	if headwindServerURL == "" {
		headwindServerURL = "http://localhost:8080"
	}

	r := gin.Default()
	r.Use(func(c *gin.Context) {
		if connectorToken == "" {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "MDM connector token is not configured"})
			return
		}
		if c.GetHeader("X-MDM-Connector-Token") != connectorToken {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}
		c.Next()
	})

	// Ensure uploads directory exists for forensic logs
	os.MkdirAll("./forensic_uploads", os.ModePerm)

	r.POST("/mdm/enroll", handleEnroll)
	// Factory resets are issued by the Device Owner app after the backend
	// verifies its backup. Do not expose a connector route that bypasses it.
	r.POST("/mdm/forensic-upload", handleForensicUpload)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8001"
	}

	log.Printf("MDM Connector running on port %s", port)
	r.Run(":" + port)
}

func handleEnroll(c *gin.Context) {
	var req EnrollRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	log.Printf("Enrolling device: %s for user ID: %d", req.DeviceID, req.UserID)

	// Simulate Headwind API call
	payload, _ := json.Marshal(map[string]interface{}{
		"deviceId": req.DeviceID,
		"imei":     req.IMEI,
	})

	resp, err := http.Post(
		fmt.Sprintf("%s/plugins/device/rest/add", headwindServerURL),
		"application/json",
		bytes.NewBuffer(payload),
	)

	if err != nil {
		log.Printf("Headwind API error: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "Headwind enrollment failed"})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("Headwind enrollment rejected device=%s status=%d", req.DeviceID, resp.StatusCode)
		c.JSON(http.StatusBadGateway, gin.H{"error": "Headwind rejected enrollment"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "enrolled", "device_id": req.DeviceID})
}

func handleForensicUpload(c *gin.Context) {
	deviceID := c.PostForm("device_id")
	if deviceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "device_id is required"})
		return
	}

	file, header, err := c.Request.FormFile("log_file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "log_file is required"})
		return
	}
	defer file.Close()

	filename := fmt.Sprintf("./forensic_uploads/%s_%s", deviceID, header.Filename)
	out, err := os.Create(filename)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save file"})
		return
	}
	defer out.Close()

	_, err = io.Copy(out, file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to write file"})
		return
	}

	log.Printf("Received forensic upload from %s: %s", deviceID, header.Filename)
	c.JSON(http.StatusOK, gin.H{"status": "upload_success", "file": header.Filename})
}
