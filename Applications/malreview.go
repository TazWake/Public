package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "time"
)

func showHelp() {
    fmt.Println("Usage: malanalyze -f <filename>")
    os.Exit(1)
}

func currentUTCTime() string {
    return time.Now().UTC().Format("2006-01-02T15:04:05Z")
}

func logAndRun(cmdStr, outputFile, logFile string) {
    timestamp := currentUTCTime()
    logEntry := fmt.Sprintf("[%s] Running command: %s\n", timestamp, cmdStr)
    logFileHandle, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Fatalf("Failed to open log file: %s", err)
    }
    defer logFileHandle.Close()
    if _, err := logFileHandle.WriteString(logEntry); err != nil {
        log.Fatalf("Failed to write to log file: %s", err)
    }

    cmd := exec.Command("bash", "-c", cmdStr)
    var out bytes.Buffer
    cmd.Stdout = &out
    cmd.Stderr = logFileHandle
    if err := cmd.Run(); err != nil {
        log.Fatalf("Command failed: %s", err)
    }

    if err := ioutil.WriteFile(outputFile, out.Bytes(), 0644); err != nil {
        log.Fatalf("Failed to write output file: %s", err)
    }
}

func resolveFullPath(filename string) string {
    fullPath, err := filepath.Abs(filename)
    if err != nil {
        log.Fatalf("Failed to resolve full path: %s", err)
    }
    if _, err := os.Stat(fullPath); os.IsNotExist(err) {
        log.Fatalf("Error: File %s not found.", filename)
    }
    return fullPath
}

func uploadToChatGPT(filepath, logpath string) {
    apiKey := os.Getenv("API")
    if apiKey == "" {
        log.Fatal("Error: API key not found. Please set the API environment variable.")
    }

    prompt := "Please review the attached file and provide an assessment of what the sample does, and if it is likely to be malicious."
    fmt.Printf("[ ] Uploading %s and %s to ChatGPT for analysis...\n", filepath, logpath)

    fileContent, err := ioutil.ReadFile(filepath)
    if err != nil {
        log.Fatalf("Failed to read file: %s", err)
    }
    logContent, err := ioutil.ReadFile(logpath)
    if err != nil {
        log.Fatalf("Failed to read log file: %s", err)
    }

    combinedContent := fmt.Sprintf("File Content:\n%s\n\nLog Content:\n%s", fileContent, logContent)

    data := map[string]interface{}{
        "model": "gpt-4",
        "messages": []map[string]string{
            {
                "role":    "user",
                "content": fmt.Sprintf("%s\n\n%s", prompt, combinedContent),
            },
        },
    }

    jsonData, err := json.Marshal(data)
    if err != nil {
        log.Fatalf("Failed to marshal JSON: %s", err)
    }

    req, err := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewBuffer(jsonData))
    if err != nil {
        log.Fatalf("Failed to create request: %s", err)
    }
    req.Header.Set("Authorization", "Bearer "+apiKey)
    req.Header.Set("Content-Type", "application/json")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        log.Fatalf("Failed to send request: %s", err)
    }
    defer resp.Body.Close()

    responseBody, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        log.Fatalf("Failed to read response body: %s", err)
    }

    timestamp := strings.ReplaceAll(currentUTCTime(), ":", "-")
    responseFilename := fmt.Sprintf("Analysis_Response_%s.json", timestamp)

    if err := ioutil.WriteFile(responseFilename, responseBody, 0644); err != nil {
        log.Fatalf("Failed to write response file: %s", err)
    }

    fmt.Printf("[ ] Response saved to %s\n", responseFilename)
}

func main() {
    if len(os.Args) != 3 {
        showHelp()
    }
    if os.Args[1] != "-f" {
        showHelp()
    }

    fn := os.Args[2]
    fullPath := resolveFullPath(fn)

    pwd, err := os.Getwd()
    if err != nil {
        log.Fatalf("Failed to get current working directory: %s", err)
    }
    evidenceStore := filepath.Join(pwd, "evidence")
    if err := os.MkdirAll(evidenceStore, 0755); err != nil {
        log.Fatalf("Failed to create evidence store: %s", err)
    }

    logFile := filepath.Join(evidenceStore, "log.txt")

    fmt.Printf("[ ] Creating evidence store at %s.\n", evidenceStore)
    fmt.Printf("[ ] Collecting data on %s now, please wait.\n", fullPath)

    logAndRun("file "+fullPath, filepath.Join(evidenceStore, "file.txt"), logFile)
    logAndRun("sha1sum "+fullPath, filepath.Join(evidenceStore, "sha1hash.txt"), logFile)
    logAndRun("readelf -a "+fullPath, filepath.Join(evidenceStore, "readelf.txt"), logFile)
    logAndRun("objdump -d "+fullPath, filepath.Join(evidenceStore, "objdump.txt"), logFile)
    logAndRun("strings -n8 "+fullPath, filepath.Join(evidenceStore, "strings.txt"), logFile)
    logAndRun("ldd "+fullPath, filepath.Join(evidenceStore, "ldd.txt"), logFile)

    fmt.Println("[ ] Static analysis complete.")

    sha256Cmd := exec.Command("sha256sum", logFile)
    sha256Out, err := sha256Cmd.Output()
    if err != nil {
        log.Fatalf("Failed to compute SHA256 hash: %s", err)
    }
    hash := strings.Fields(string(sha256Out))[0]

    fmt.Printf("[ ] Evidence is stored in %s and the log file is at %s.\n", evidenceStore, logFile)
    fmt.Printf("[*] The SHA256 hash of the log file is %s.\n", hash)

    uploadToChatGPT(fullPath, logFile)
}
