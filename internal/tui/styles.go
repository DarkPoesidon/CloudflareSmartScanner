package tui

import "github.com/charmbracelet/lipgloss"

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00BFFF")).
			Align(lipgloss.Center).
			Padding(1, 2)

	wrapperStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#00BFFF")).
			Padding(1, 2)

	stateRunningStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Bold(true)
	statePausedStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFF00")).Bold(true)
	stateStoppedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000")).Bold(true)

	tableHeaderStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")).Bold(true)
	
	greenText   = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Bold(true)
	yellowText  = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFF00")).Bold(true)
	redText     = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000")).Bold(true)
	cyanText    = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF"))
	magentaText = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF00FF")).Bold(true)

	// DNS Integrity badge styles
	integrityCleanStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF88")).Bold(true)
	integrityPoisonedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF3333")).Bold(true)
)

func statusColor(status int) lipgloss.Style {
	if status < 300 {
		return greenText
	}
	if status < 400 {
		return cyanText
	}
	if status < 500 {
		return yellowText
	}
	return redText
}

func latencyColor(latency int) lipgloss.Style {
	if latency < 200 {
		return greenText
	}
	if latency < 500 {
		return yellowText
	}
	return redText
}

// protocolColor returns a styled badge for DNS protocol names.
func protocolColor(proto string) lipgloss.Style {
	switch proto {
	case "UDP":
		return yellowText
	case "TCP":
		return cyanText
	case "DoT":
		return greenText
	case "DoH":
		return magentaText
	default:
		return lipgloss.NewStyle()
	}
}
