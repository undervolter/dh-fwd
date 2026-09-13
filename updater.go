package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var Version = "v2.2.0"

const (
	githubRepo    = "undervolter/dh-fwd"
	apiLatestURL  = "https://api.github.com/repos/" + githubRepo + "/releases/latest"
	updateCheckTO = 2 * time.Second
)

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

type githubRelease struct {
	TagName string        `json:"tag_name"`
	Name    string        `json:"name"`
	Assets  []githubAsset `json:"assets"`
}

func timeTag() string {
	return time.Now().Format("[15:04]")
}

// checkUpdate checks GitHub for newer releases and handles prompt/self-update.
// Returns true if dh-fwd should proceed to connection, false if it updated and exited.
func checkUpdate() bool {
	client := &http.Client{Timeout: updateCheckTO}
	req, err := http.NewRequest("GET", apiLatestURL, nil)
	if err != nil {
		fmt.Printf("%s dh-fwd %s (latest)\n", timeTag(), Version)
		return true
	}
	req.Header.Set("User-Agent", "dh-fwd/"+Version)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_ = resp.Body.Close()
		}
		fmt.Printf("%s dh-fwd %s (latest)\n", timeTag(), Version)
		return true
	}
	defer resp.Body.Close()

	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		fmt.Printf("%s dh-fwd %s (latest)\n", timeTag(), Version)
		return true
	}

	latestTag := strings.TrimSpace(rel.TagName)
	if latestTag == "" || !isNewerVersion(latestTag, Version) {
		fmt.Printf("%s dh-fwd %s (latest)\n", timeTag(), Version)
		return true
	}

	// New release available
	fmt.Printf("%s dh-fwd %s\n", timeTag(), Version)
	fmt.Printf("new release! %s -> %s\n", Version, latestTag)
	fmt.Print("do you want to update? (y/n): ")

	reader := bufio.NewReader(os.Stdin)
	answer, _ := reader.ReadString('\n')
	answer = strings.ToLower(strings.TrimSpace(answer))

	if answer != "y" && answer != "yes" && answer != "д" && answer != "да" {
		return true
	}

	assetName := targetAssetName()
	var downloadURL string
	for _, a := range rel.Assets {
		if a.Name == assetName {
			downloadURL = a.BrowserDownloadURL
			break
		}
	}

	if downloadURL == "" {
		fmt.Printf("could not find release asset %s for %s/%s\n", assetName, runtime.GOOS, runtime.GOARCH)
		return true
	}

	fmt.Printf("downloading %s...\n", assetName)
	if err := selfUpdate(downloadURL); err != nil {
		fmt.Printf("update failed: %v\n", err)
		return true
	}

	fmt.Printf("successfully updated to %s! please restart dh-fwd.\n", latestTag)
	os.Exit(0)
	return false
}

func targetAssetName() string {
	switch runtime.GOOS {
	case "windows":
		switch runtime.GOARCH {
		case "arm64":
			return "dh-fwd_win_arm64.exe"
		default:
			return "dh-fwd_win_x64.exe"
		}
	case "linux":
		switch runtime.GOARCH {
		case "arm64":
			return "dh-fwd_linux_arm64"
		default:
			return "dh-fwd_linux_x64"
		}
	default:
		return ""
	}
}

func isNewerVersion(latest, current string) bool {
	lParts := parseSemVer(latest)
	cParts := parseSemVer(current)
	for i := 0; i < 3; i++ {
		if lParts[i] > cParts[i] {
			return true
		}
		if lParts[i] < cParts[i] {
			return false
		}
	}
	return false
}

func parseSemVer(v string) [3]int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.Split(v, ".")
	var res [3]int
	for i := 0; i < len(parts) && i < 3; i++ {
		n, _ := strconv.Atoi(parts[i])
		res[i] = n
	}
	return res
}

func selfUpdate(downloadURL string) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate binary: %w", err)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("eval symlinks: %w", err)
	}

	resp, err := http.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad HTTP status: %s", resp.Status)
	}

	dir := filepath.Dir(exePath)
	tmpFile, err := os.CreateTemp(dir, "dh-fwd-update-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
	}()

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		return fmt.Errorf("save download: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	// Chmod for linux/darwin
	_ = os.Chmod(tmpFile.Name(), 0755)

	if runtime.GOOS == "windows" {
		oldPath := exePath + ".old"
		_ = os.Remove(oldPath) // remove any leftover old binary
		if err := os.Rename(exePath, oldPath); err != nil {
			return fmt.Errorf("rename current exe: %w", err)
		}
		if err := os.Rename(tmpFile.Name(), exePath); err != nil {
			// rollback
			_ = os.Rename(oldPath, exePath)
			return fmt.Errorf("install new exe: %w", err)
		}
	} else {
		if err := os.Rename(tmpFile.Name(), exePath); err != nil {
			return fmt.Errorf("replace binary: %w", err)
		}
	}

	return nil
}
