package tui

import (
	"fmt"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"reachability-scanner/engine"
)

// Messages sent from Engine -> Bubbletea
type resultMsg struct {
	result *engine.ScanResult
}
type progressMsg struct {
	done  int
	total int
}
type stateMsg struct {
	state string
}
type completeMsg struct {
	openCount  int
	deadCount  int
	totalCount int
}
type tickMsg time.Time

// bridge interface allowing Engine to talk to UI
type teaBridge struct {
	p *tea.Program
}

func (b *teaBridge) OnResult(r *engine.ScanResult) {
	b.p.Send(resultMsg{result: r})
}
func (b *teaBridge) OnProgress(done, total int) {
	b.p.Send(progressMsg{done: done, total: total})
}
func (b *teaBridge) OnStateChange(state string) {
	b.p.Send(stateMsg{state: state})
}
func (b *teaBridge) OnComplete(openCount, deadCount, totalCount int) {
	b.p.Send(completeMsg{openCount: openCount, deadCount: deadCount, totalCount: totalCount})
}

// ════════════════════════════════════════════════════════════════════════════════
// DNS Display Entry — used by the TUI to render the DNS Resolver Map
// ════════════════════════════════════════════════════════════════════════════════

// DnsDisplayEntry holds one row of the DNS Resolver Map table.
type DnsDisplayEntry struct {
	ResolverIP string
	Protocol   string
	IsPoisoned bool
	TTFB       int    // milliseconds
	AnswerIP   string // First answer IP from the response
	Error      string // Non-empty if the probe failed
}

// Model is the Bubbletea TUI state
type Model struct {
	engine   *engine.Engine
	keys     KeyMap
	progress progress.Model

	state     string
	done      int
	total     int
	openCount int
	deadCount int
	startTime time.Time
	width     int
	height    int

	// Standard HTTP mode — recent hits ring buffer
	recentHits [128]*engine.ScanResult
	hitIndex   int
	hitCount   int

	// DNS Discovery Mode state
	dnsMode       bool
	dnsResults    [128]DnsDisplayEntry
	dnsIndex      int
	dnsEntryCount int
	dnsCleanCount int
	dnsPoisoned   int

	quitting bool
	finished bool
}

// NewModel initializes the TUI
func NewModel(cfg *engine.ScanConfig) *Model {
	prog := progress.New(progress.WithDefaultGradient())
	return &Model{
		keys:      DefaultKeyMap,
		progress:  prog,
		state:     "STARTING",
		startTime: time.Now(),
		dnsMode:   cfg.DnsDiscoveryMode,
	}
}

// Run configures the engine, sets up the bridge, and starts the TUI
func (m *Model) Run(cfg *engine.ScanConfig) error {
	p := tea.NewProgram(m, tea.WithAltScreen())
	bridge := &teaBridge{p: p}
	m.engine = engine.NewEngine(cfg, bridge)

	go m.engine.Start()

	_, err := p.Run()
	return err
}

func (m *Model) Init() tea.Cmd {
	return tickCmd()
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Millisecond*200, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.progress.Width = msg.Width - 10

	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keys.Quit):
			m.quitting = true
			return m, tea.Sequence(
				func() tea.Msg {
					m.engine.Stop()
					return nil
				},
				tea.Quit,
			)
		case key.Matches(msg, m.keys.Pause):
			return m, func() tea.Msg {
				m.engine.Pause()
				return nil
			}
		case key.Matches(msg, m.keys.Resume):
			return m, func() tea.Msg {
				m.engine.Resume()
				return nil
			}
		}

	case resultMsg:
		if m.dnsMode {
			m.handleDnsResult(msg.result)
		} else {
			m.handleHttpResult(msg.result)
		}

	case progressMsg:
		m.done = msg.done
		m.total = msg.total

	case stateMsg:
		m.state = msg.state

	case completeMsg:
		m.finished = true
		m.quitting = true
		return m, tea.Quit

	case tickMsg:
		if m.quitting {
			return m, tea.Quit
		}
		return m, tickCmd()
	}

	return m, nil
}

// handleHttpResult processes a standard HTTP scan result.
func (m *Model) handleHttpResult(r *engine.ScanResult) {
	if r.Status > 0 {
		m.openCount++
		m.recentHits[m.hitIndex] = r
		m.hitIndex++
		if m.hitIndex >= 128 {
			m.hitIndex = 0
		}
		if m.hitCount < 128 {
			m.hitCount++
		}
	} else {
		m.deadCount++
	}
}

// handleDnsResult processes a DNS discovery result and populates the DNS map.
func (m *Model) handleDnsResult(r *engine.ScanResult) {
	if r.DnsProtocol == "" {
		return // Skip non-DNS results
	}

	if r.Error == "" && r.Status > 0 {
		m.openCount++
		if r.IsPoisoned {
			m.dnsPoisoned++
		} else {
			m.dnsCleanCount++
		}
	} else {
		m.deadCount++
	}

	// Add to DNS display ring buffer
	entry := DnsDisplayEntry{
		ResolverIP: r.Label,
		Protocol:   r.DnsProtocol,
		IsPoisoned: r.IsPoisoned,
		TTFB:       r.LatencyMs,
		AnswerIP:   r.ResolvedIP,
		Error:      r.Error,
	}

	m.dnsResults[m.dnsIndex] = entry
	m.dnsIndex++
	if m.dnsIndex >= 128 {
		m.dnsIndex = 0
	}
	if m.dnsEntryCount < 128 {
		m.dnsEntryCount++
	}
}

func (m *Model) View() string {
	if m.quitting && m.finished {
		if m.dnsMode {
			return fmt.Sprintf("\n  DNS Discovery complete! Clean: %d, Poisoned: %d, Failed: %d\n",
				m.dnsCleanCount, m.dnsPoisoned, m.deadCount)
		}
		return fmt.Sprintf("\n  Scan complete! Open: %d, Dead: %d\n", m.openCount, m.deadCount)
	}
	if m.quitting {
		return "\n  Stopping and saving...\n"
	}

	appWidth := m.width - 6
	if appWidth < 60 {
		appWidth = 60
	}

	// Title changes based on scan mode
	var title string
	if m.dnsMode {
		title = titleStyle.Width(appWidth).Render("🛡️  HIGH-PRECISION DNS DISCOVERY ENGINE")
	} else {
		title = titleStyle.Width(appWidth).Render("🚀 MASTER DNS VPN SCANNER ENTERPRISE")
	}

	// Progress bar
	var progStr string
	if m.total > 0 {
		pct := float64(m.done) / float64(m.total)
		progStr = m.progress.ViewAs(pct)
	} else {
		progStr = "Calculating..."
	}

	pctText := ""
	if m.total > 0 {
		pctText = fmt.Sprintf(" %d/%d ", m.done, m.total)
	}
	elapsed := time.Since(m.startTime).Round(time.Second)

	// Controls and state
	controls := "[P] Pause  •  [R] Resume  •  [Q] Stop & Save"

	stateBadge := m.state
	switch m.state {
	case "RUNNING":
		stateBadge = stateRunningStyle.Render(m.state)
	case "PAUSED":
		stateBadge = statePausedStyle.Render(m.state)
	case "STOPPED":
		stateBadge = stateStoppedStyle.Render(m.state)
	}

	// Mode-specific stats line
	var statsFormat string
	if m.dnsMode {
		statsFormat = lipgloss.NewStyle().Width(appWidth).Render(fmt.Sprintf("%s | State: %s | CLEAN: %s | POISONED: %s | FAIL: %s",
			controls,
			stateBadge,
			greenText.Render(fmt.Sprintf("%d", m.dnsCleanCount)),
			redText.Render(fmt.Sprintf("%d", m.dnsPoisoned)),
			yellowText.Render(fmt.Sprintf("%d", m.deadCount)),
		))
	} else {
		statsFormat = lipgloss.NewStyle().Width(appWidth).Render(fmt.Sprintf("%s | State: %s | UP: %s | DOWN: %s",
			controls,
			stateBadge,
			greenText.Render(fmt.Sprintf("%d", m.openCount)),
			redText.Render(fmt.Sprintf("%d", m.deadCount)),
		))
	}

	// ── Build the data table ──
	var dataTable string
	if m.dnsMode {
		dataTable = m.renderDnsMap(appWidth)
	} else {
		dataTable = m.renderHttpTable(appWidth)
	}

	body := fmt.Sprintf("\n%s%s elapsed: %v\n\n%s\n\n%s",
		progStr, pctText, elapsed, statsFormat, dataTable)

	return wrapperStyle.Width(m.width - 2).Render(title+"\n"+body) + "\n"
}

// ════════════════════════════════════════════════════════════════════════════════
// DNS RESOLVER MAP — TUI Table for DNS Discovery Mode
// ════════════════════════════════════════════════════════════════════════════════

func (m *Model) renderDnsMap(appWidth int) string {
	sectionTitle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#00BFFF")).
		Render("🛡️  DNS RESOLVER MAP")

	// Table header
	// Columns: Resolver(18) + Proto(6) + TTFB(8) + Integrity(12) + AnswerIP(18) + Error(rest) + gaps(10) ≈ 72 fixed
	headerFmt := fmt.Sprintf("  %%-%ds  %%-6s  %%8s  %%-12s  %%-18s  %%s\n", 18)
	header := tableHeaderStyle.Render(fmt.Sprintf(headerFmt, "Resolver", "Proto", "TTFB", "Integrity", "Answer IP", "Status"))

	// Calculate available rows based on window height
	// ~12 lines are used by header, progress, controls, and margins
	availableRows := m.height - 13
	if availableRows < 5 {
		availableRows = 5
	}
	if availableRows > 128 {
		availableRows = 128
	}

	// Build ordered entries from ring buffer
	ordered := make([]DnsDisplayEntry, 128)
	if m.dnsEntryCount < 128 {
		for i := 0; i < m.dnsEntryCount; i++ {
			ordered[i] = m.dnsResults[i]
		}
	} else {
		for i := 0; i < 128; i++ {
			idx := (m.dnsIndex + i) % 128
			ordered[i] = m.dnsResults[idx]
		}
	}

	dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#555555"))
	rows := ""

	// Show most recent at top, constrained by availableRows
	startIndex := m.dnsEntryCount - 1
	endIndex := m.dnsEntryCount - availableRows
	if endIndex < 0 {
		endIndex = 0
	}

	for i := startIndex; i >= endIndex; i-- {
		entry := ordered[i]
		if entry.ResolverIP == "" {
			continue
		}

		// Resolver IP
		resolver := entry.ResolverIP
		if len(resolver) > 18 {
			resolver = resolver[:15] + "..."
		}

		// Protocol badge (colored)
		proto := protocolColor(entry.Protocol).Render(fmt.Sprintf("%-5s", entry.Protocol))

		// TTFB
		ttfb := ""
		if entry.Error == "" {
			ttfb = latencyColor(entry.TTFB).Render(fmt.Sprintf("%dms", entry.TTFB))
		} else {
			ttfb = dimStyle.Render("—")
		}

		// Integrity badge
		integrity := ""
		if entry.Error != "" {
			integrity = dimStyle.Render("—")
		} else if entry.IsPoisoned {
			integrity = integrityPoisonedStyle.Render("✗ POISONED")
		} else {
			integrity = integrityCleanStyle.Render("✓ CLEAN")
		}

		// Answer IP
		answerIP := entry.AnswerIP
		if answerIP == "" {
			answerIP = "—"
		}
		answerIPStyled := cyanText.Render(answerIP)

		// Status / Error
		status := ""
		if entry.Error != "" {
			errStr := entry.Error
			if len(errStr) > 24 {
				errStr = errStr[:21] + "..."
			}
			status = redText.Render(errStr)
		} else {
			status = greenText.Render("OK")
		}

		rows += fmt.Sprintf(headerFmt, resolver, proto, ttfb, integrity, answerIPStyled, status)
	}

	if rows == "" {
		rows = dimStyle.Render("  Waiting for DNS probe results...\n")
	}

	return sectionTitle + "\n" + header + rows
}

// ════════════════════════════════════════════════════════════════════════════════
// HTTP TABLE — Standard Reachability Scan Table (unchanged logic)
// ════════════════════════════════════════════════════════════════════════════════

func (m *Model) renderHttpTable(appWidth int) string {
	sectionTitle := "Recent Active Nodes:"

	// Dynamic table with IP:Port column
	// Fixed columns: Latency(8) + gaps(8) + Status(12) + IP:Port(22) = 50
	fixedCols := 50
	availableTableWidth := appWidth - fixedCols
	if availableTableWidth < 20 {
		availableTableWidth = 20
	}
	labelWidth := int(float64(availableTableWidth) * 0.45)
	urlWidth := availableTableWidth - labelWidth
	if labelWidth < 8 {
		labelWidth = 8
	}
	if urlWidth < 8 {
		urlWidth = 8
	}

	headerFormat := fmt.Sprintf("%%8s  %%-12s  %%-22s  %%-%ds  %%-%ds\n", labelWidth, urlWidth)
	hitsTable := tableHeaderStyle.Render(fmt.Sprintf(headerFormat, "Latency", "Status", "IP : Port", "Label", "URL"))

	// Calculate available rows to fill the terminal perfectly
	availableRows := m.height - 13
	if availableRows < 5 {
		availableRows = 5
	}
	if availableRows > 128 {
		availableRows = 128
	}

	// Build ordered ring buffer of recent hits
	orderedHits := make([]*engine.ScanResult, 128)
	if m.hitCount < 128 {
		for i := 0; i < m.hitCount; i++ {
			orderedHits[i] = m.recentHits[i]
		}
	} else {
		for i := 0; i < 128; i++ {
			idx := (m.hitIndex + i) % 128
			orderedHits[i] = m.recentHits[idx]
		}
	}

	dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#555555"))

	// Determine iteration constraints
	startIndex := len(orderedHits) - 1
	if m.hitCount < 128 {
		startIndex = m.hitCount - 1
	}
	count := 0

	for i := startIndex; i >= 0 && count < availableRows; i-- {
		hit := orderedHits[i]
		count++
		if hit == nil {
			hitsTable += fmt.Sprintf(headerFormat, "-", "-", "-", "-", "-")
		} else {
			lat := latencyColor(hit.LatencyMs).Render(fmt.Sprintf("%dms", hit.LatencyMs))
			stat := statusColor(hit.Status).Render(fmt.Sprintf("HTTP %d", hit.Status))

			ipPort := fmt.Sprintf("%s:%d", hit.ResolvedIP, hit.Port)
			if len(ipPort) > 22 {
				ipPort = ipPort[:19] + "..."
			}
			ipPortStyled := cyanText.Render(ipPort)

			lbl := hit.Label
			if len(lbl) > labelWidth {
				lbl = lbl[:labelWidth-3] + "..."
			}

			url := hit.URL
			if len(url) > urlWidth {
				url = url[:urlWidth-3] + "..."
			}

			hitsTable += fmt.Sprintf(headerFormat, lat, stat, ipPortStyled, lbl, dimStyle.Render(url))
		}
	}

	return sectionTitle + "\n" + hitsTable
}
