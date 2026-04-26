package engine

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"
)

// Engine is the core scanner orchestrator.
type Engine struct {
	config  *ScanConfig
	handler ResultHandler

	state      string // RUNNING, PAUSED, STOPPED
	mu         sync.Mutex
	resumeChan chan struct{}

	cancel context.CancelFunc
	wg     sync.WaitGroup

	totalCount int
}

// NewEngine creates a new scanner engine instance.
func NewEngine(config *ScanConfig, handler ResultHandler) *Engine {
	return &Engine{
		config:     config,
		handler:    handler,
		state:      "STOPPED",
		resumeChan: make(chan struct{}),
	}
}

// Start begins the scanning process.
// Blocks until all scans are finished or stopped.
func (e *Engine) Start() {
	e.mu.Lock()
	e.state = "RUNNING"
	e.mu.Unlock()
	e.handler.OnStateChange("RUNNING")

	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel

	cachePath := filepath.Join(e.config.OutputDir, e.config.CacheFile)
	prioritized, _ := LoadCache(cachePath, false) // cache is never expanded to all ports
	mainTargets, err := ParseTargets(
		filepath.Join(e.config.OutputDir, e.config.InputFile),
		e.config.ScanAllPorts,
	)
	if err != nil {
		e.handler.OnStateChange(fmt.Sprintf("FATAL: Target Parse Err: %v", err))
		return
	}

	targets := DeduplicateTargets(prioritized, mainTargets)
	e.totalCount = len(targets)
	if e.totalCount == 0 {
		return
	}

	// ── DNS Discovery Mode ──
	if e.config.DnsDiscoveryMode {
		e.startDnsDiscovery(ctx, targets)
		return
	}

	// ── Standard HTTP Reachability Scan ──
	e.startHttpScan(ctx, targets)
}

// startHttpScan runs the standard HTTP reachability scanning path.
func (e *Engine) startHttpScan(ctx context.Context, targets []Target) {
	// Use a bounded job buffer — avoid allocating a channel the size of all targets
	// when scanning millions of IPs across 13 ports.
	bufSize := e.config.MaxConcurrent * 4
	if bufSize > e.totalCount {
		bufSize = e.totalCount
	}
	jobs := make(chan Target, bufSize)
	results := make(chan ScanResult, bufSize)

	// Start workers
	for i := 0; i < e.config.MaxConcurrent; i++ {
		e.wg.Add(1)
		go e.scanWorker(ctx, jobs, results)
	}

	// Feed jobs in a separate goroutine so we don't block on a full channel
	go func() {
		defer close(jobs)
		for _, t := range targets {
			select {
			case jobs <- t:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Collect results
	e.collectResults(ctx, results)
}

// startDnsDiscovery runs the DNS resolver discovery path.
// Each resolver IP is probed across 4 protocols, producing 4 results per target.
func (e *Engine) startDnsDiscovery(ctx context.Context, targets []Target) {
	// Initialize the Truth Table
	truth := NewTruthTable(e.config.TargetDomain)
	if err := truth.FetchTruth(); err != nil {
		// Suppress raw stdout output to prevent UI tearing during engine start.
		// Integrity Verification falls back implicitly.
	}

	// In DNS mode, each IP generates 4 results (one per protocol)
	// Adjust total for progress tracking
	e.totalCount = len(targets) * 4

	bufSize := e.config.MaxConcurrent * 4
	if bufSize > len(targets) {
		bufSize = len(targets)
	}
	if bufSize < 16 {
		bufSize = 16
	}
	jobs := make(chan Target, bufSize)
	results := make(chan ScanResult, bufSize*4)

	// Start DNS workers
	for i := 0; i < e.config.MaxConcurrent; i++ {
		e.wg.Add(1)
		go e.dnsWorker(ctx, jobs, results, truth)
	}

	// Feed jobs
	go func() {
		defer close(jobs)
		for _, t := range targets {
			select {
			case jobs <- t:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Collect results
	e.collectResults(ctx, results)
}

// collectResults is the shared result collection loop used by both scan modes.
func (e *Engine) collectResults(ctx context.Context, results chan ScanResult) {
	var openResults []ScanResult
	var deadResults []ScanResult
	doneCount := 0

	// Close results channel when all workers finish
	go func() {
		e.wg.Wait()
		close(results)
	}()

	for res := range results {
		if res.Error == "ABORTED" {
			continue
		}
		doneCount++

		e.handler.OnResult(&res)
		e.handler.OnProgress(doneCount, e.totalCount)

		// Determine success based on the active scan mode:
		//   HTTP Reachability Mode: successful iff Error is empty.
		//   DNS Discovery Mode:     successful iff Error is empty AND the
		//                           resolver is NOT poisoned.
		// Any node with an Error OR that is Poisoned belongs in deadResults.
		isSuccess := res.Error == ""
		if e.config.DnsDiscoveryMode {
			isSuccess = isSuccess && !res.IsPoisoned
		}

		if isSuccess {
			openResults = append(openResults, res)
		} else {
			deadResults = append(deadResults, res)
		}
	}

	e.mu.Lock()
	e.state = "STOPPED"
	e.mu.Unlock()
	e.handler.OnStateChange("STOPPED")

	timestamp := time.Now().Format("20060102_150405")
	openPath := fmt.Sprintf("reachable_%s.txt", timestamp)
	fullPath := fmt.Sprintf("full_log_%s.txt", timestamp)

	WriteReports(e.config.OutputDir, openPath, fullPath, e.config.CacheFile, openResults, deadResults, e.totalCount)

	e.handler.OnComplete(len(openResults), len(deadResults), e.totalCount)
}

// Pause puts the engine in a paused state.
func (e *Engine) Pause() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state == "RUNNING" {
		e.state = "PAUSED"
		e.handler.OnStateChange("PAUSED")
	}
}

// Resume wakes the engine from a paused state.
func (e *Engine) Resume() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state == "PAUSED" {
		e.state = "RUNNING"
		close(e.resumeChan)
		e.resumeChan = make(chan struct{})
		e.handler.OnStateChange("RUNNING")
	}
}

// Stop safely aborts all running workers and shuts down.
func (e *Engine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state != "STOPPED" {
		e.state = "STOPPED"
		if e.cancel != nil {
			e.cancel()
		}
		close(e.resumeChan)
		e.resumeChan = make(chan struct{})
		e.handler.OnStateChange("STOPPED")
	}
}

// State returns the current engine state.
func (e *Engine) State() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.state
}
