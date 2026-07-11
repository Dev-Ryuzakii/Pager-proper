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

// EnrollRequest represents the JSON payload to enroll a device.
type EnrollRequest struct {
	DeviceID string `json:"device_id"`
	IMEI     string `json:"imei"`
	UserID   int    `json:"user_id"`
}

// WipeRequest represents the JSON payload to wipe a device.
type WipeRequest struct {
	DeviceID string `json:"device_id"`
	Reason   string `json:"reason"`
}

func main() {
	if headwindServerURL == "" {
		headwindServerURL = "http://localhost:8080/rest"
	}

	r := gin.Default()

	// Ensure uploads directory exists for forensic logs
	os.MkdirAll("./forensic_uploads", os.ModePerm)

	r.POST("/mdm/enroll", handleEnroll)
	r.POST("/mdm/wipe", handleWipe)
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
		// For prototyping, we'll return success even if Headwind isn't reachable
		c.JSON(http.StatusOK, gin.H{"status": "simulated_success", "device_id": req.DeviceID})
		return
	}
	defer resp.Body.Close()

	c.JSON(http.StatusOK, gin.H{"status": "enrolled", "device_id": req.DeviceID})
}

func handleWipe(c *gin.Context) {
	var req WipeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	log.Printf("Wiping device: %s Reason: %s", req.DeviceID, req.Reason)

	// Simulate Headwind API wipe command
	// Headwind API typically uses something like /plugins/device/rest/wipe or MQTT
	payload, _ := json.Marshal(map[string]interface{}{
		"deviceId": req.DeviceID,
		"action":   "factory_reset",
	})

	resp, err := http.Post(
		fmt.Sprintf("%s/plugins/device/rest/command", headwindServerURL),
		"application/json",
		bytes.NewBuffer(payload),
	)

	if err != nil {
		log.Printf("Headwind API error: %v", err)
		c.JSON(http.StatusOK, gin.H{"status": "simulated_wipe_triggered", "device_id": req.DeviceID})
		return
	}
	defer resp.Body.Close()

	c.JSON(http.StatusOK, gin.H{"status": "wipe_triggered", "device_id": req.DeviceID})
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
