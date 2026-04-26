package engine

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// LoadCache returns the parsed domains from the cache file.
// Cache is never port-expanded (scanAllPorts = false).
func LoadCache(path string, scanAllPorts bool) ([]Target, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}
	return ParseTargets(path, scanAllPorts)
}

// SaveCache saves the successful domains to the last_passed cache.
// The caller is responsible for passing only clean/successful results.
func SaveCache(path string, results []ScanResult) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	writer.WriteString("# Auto-saved cache of last passed domains\n")
	for _, result := range results {
		writer.WriteString(fmt.Sprintf("%s | %s\n", result.Label, result.URL))
	}
	return writer.Flush()
}

// SaveOpenReport generates the text report for open targets.
// Now includes ResolvedIP and Port columns.
func SaveOpenReport(path string, openResults []ScanResult, deadResults []ScanResult, total int) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	actualTested := len(openResults) + len(deadResults)
	writer := bufio.NewWriter(file)

	writer.WriteString("Reachability Report — OPEN SITES\n")
	writer.WriteString(fmt.Sprintf("Generated        : %s\n", time.Now().Format("2006-01-02 15:04:05")))
	writer.WriteString(fmt.Sprintf("Total tested     : %d / %d\n", actualTested, total))
	writer.WriteString(fmt.Sprintf("Open (reachable) : %d\n", len(openResults)))
	writer.WriteString(fmt.Sprintf("Closed / Dead    : %d\n", len(deadResults)))
	writer.WriteString("============================================================================================\n\n")
	writer.WriteString(fmt.Sprintf("%-4s  %8s  %5s  %-22s  %-30s  URL\n", "#", "Latency", "HTTP", "IP : Port", "Label"))
	writer.WriteString("--------------------------------------------------------------------------------------------\n")

	sort.Slice(openResults, func(i, j int) bool {
		return openResults[i].LatencyMs < openResults[j].LatencyMs
	})

	for i, r := range openResults {
		ipPort := fmt.Sprintf("%s:%d", r.ResolvedIP, r.Port)
		writer.WriteString(fmt.Sprintf("%-4d  %6dms  %5d  %-22s  %-30s  %s\n", i+1, r.LatencyMs, r.Status, ipPort, r.Label, r.URL))
	}

	writer.WriteString("\n\n============================================================================================\n")
	writer.WriteString("CLOSED / UNREACHABLE (DNS/TCP/TLS/HTTP Errors)\n")
	writer.WriteString("============================================================================================\n")

	sort.Slice(deadResults, func(i, j int) bool {
		return deadResults[i].Label < deadResults[j].Label
	})

	for _, r := range deadResults {
		ipPort := fmt.Sprintf("%s:%d", r.ResolvedIP, r.Port)
		writer.WriteString(fmt.Sprintf("  %-30s  %-22s  [%s]\n", r.Label, ipPort, r.Error))
	}

	return writer.Flush()
}

// SaveFullReport generates the full log report with IP:Port.
func SaveFullReport(path string, openResults []ScanResult, deadResults []ScanResult) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	writer.WriteString("Reachability Report — FULL LOG\n")
	writer.WriteString(fmt.Sprintf("Generated : %s\n", time.Now().Format("2006-01-02 15:04:05")))
	writer.WriteString("============================================================================================\n\n")
	writer.WriteString(fmt.Sprintf("%-6s  %8s  %-15s  %-22s  %-30s  URL\n", "Tag", "Latency", "HTTP/Err", "IP : Port", "Label"))
	writer.WriteString("--------------------------------------------------------------------------------------------\n")

	var allRows []ScanResult
	allRows = append(allRows, openResults...)
	allRows = append(allRows, deadResults...)

	sort.Slice(allRows, func(i, j int) bool {
		return allRows[i].Label < allRows[j].Label
	})

	for _, r := range allRows {
		tag := "OPEN"
		statStr := fmt.Sprintf("%d", r.Status)
		if r.Error != "" {
			tag = "DEAD"
			statStr = r.Error
			if statStr == "" {
				statStr = "DEAD"
			}
		}
		ipPort := fmt.Sprintf("%s:%d", r.ResolvedIP, r.Port)
		writer.WriteString(fmt.Sprintf("%-6s  %6dms  %-15s  %-22s  %-30s  %s\n", tag, r.LatencyMs, statStr, ipPort, r.Label, r.URL))
	}

	return writer.Flush()
}

// WriteReports is a helper to write all logs at once to a specific directory.
func WriteReports(outDir, openPath, fullPath, cachePath string, openResults []ScanResult, deadResults []ScanResult, total int) {
	openFile := filepath.Join(outDir, openPath)
	fullFile := filepath.Join(outDir, fullPath)
	cacheFile := filepath.Join(outDir, cachePath)

	SaveOpenReport(openFile, openResults, deadResults, total)
	SaveFullReport(fullFile, openResults, deadResults)
	SaveCache(cacheFile, openResults)
}
