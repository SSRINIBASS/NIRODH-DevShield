package report

import (
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/NIRODH/devshield/pkg/schema"
)

// WriteHTML generates a self-contained HTML report with embedded CSS and Chart.js.
func WriteHTML(result *schema.ScanResult, outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create HTML file: %w", err)
	}
	defer f.Close()

	// Parse and execute the HTML template
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"upper":          strings.ToUpper,
		"toString":       func(v interface{}) string { return fmt.Sprintf("%s", v) },
		"severityColor":  severityColor,
		"severityBgColor": severityBgColor,
		"formatDuration": formatDuration,
		"add":            func(a, b int) int { return a + b },
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse HTML template: %w", err)
	}

	// Prepare template data
	data := struct {
		Result    *schema.ScanResult
		Generated string
	}{
		Result:    result,
		Generated: time.Now().Format("2006-01-02 15:04:05 MST"),
	}

	return tmpl.Execute(f, data)
}

func severityColor(s schema.Severity) string {
	switch s {
	case schema.SeverityCritical:
		return "#dc2626"
	case schema.SeverityHigh:
		return "#ea580c"
	case schema.SeverityMedium:
		return "#d97706"
	case schema.SeverityLow:
		return "#2563eb"
	case schema.SeverityInfo:
		return "#6b7280"
	default:
		return "#6b7280"
	}
}

func severityBgColor(s schema.Severity) string {
	switch s {
	case schema.SeverityCritical:
		return "#fef2f2"
	case schema.SeverityHigh:
		return "#fff7ed"
	case schema.SeverityMedium:
		return "#fffbeb"
	case schema.SeverityLow:
		return "#eff6ff"
	case schema.SeverityInfo:
		return "#f9fafb"
	default:
		return "#f9fafb"
	}
}

func formatDuration(seconds float64) string {
	d := time.Duration(seconds * float64(time.Second))
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DevShield Security Report</title>
    <style>
        :root {
            --bg: #0f172a;
            --surface: #1e293b;
            --surface-2: #334155;
            --border: #475569;
            --text: #f1f5f9;
            --text-muted: #94a3b8;
            --accent: #818cf8;
            --accent-glow: rgba(129, 140, 248, 0.2);
            --critical: #ef4444;
            --critical-bg: rgba(239, 68, 68, 0.15);
            --high: #f97316;
            --high-bg: rgba(249, 115, 22, 0.15);
            --medium: #eab308;
            --medium-bg: rgba(234, 179, 8, 0.15);
            --low: #3b82f6;
            --low-bg: rgba(59, 130, 246, 0.15);
            --info: #6b7280;
            --info-bg: rgba(107, 114, 128, 0.15);
            --success: #22c55e;
            --radius: 12px;
            --shadow: 0 4px 6px -1px rgba(0,0,0,0.3), 0 2px 4px -2px rgba(0,0,0,0.2);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            min-height: 100vh;
        }

        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }

        /* Header */
        .header {
            background: linear-gradient(135deg, var(--surface), var(--surface-2));
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 2rem;
            margin-bottom: 1.5rem;
            box-shadow: var(--shadow);
        }

        .header h1 {
            font-size: 1.75rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            background: linear-gradient(135deg, var(--accent), #a78bfa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .header .meta {
            color: var(--text-muted);
            font-size: 0.875rem;
            display: flex;
            gap: 1.5rem;
            flex-wrap: wrap;
        }

        .header .meta span { display: flex; align-items: center; gap: 0.375rem; }

        /* Summary Cards */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }

        .summary-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 1.25rem;
            text-align: center;
            box-shadow: var(--shadow);
            transition: transform 0.2s, border-color 0.2s;
        }

        .summary-card:hover {
            transform: translateY(-2px);
            border-color: var(--accent);
        }

        .summary-card .count {
            font-size: 2rem;
            font-weight: 800;
            line-height: 1;
            margin-bottom: 0.25rem;
        }

        .summary-card .label {
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
        }

        .count-critical { color: var(--critical); }
        .count-high { color: var(--high); }
        .count-medium { color: var(--medium); }
        .count-low { color: var(--low); }
        .count-info { color: var(--info); }
        .count-total { color: var(--accent); }

        /* Tools Section */
        .section {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            margin-bottom: 1.5rem;
            box-shadow: var(--shadow);
            overflow: hidden;
        }

        .section-header {
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border);
            font-weight: 600;
            font-size: 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .tools-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 0.75rem;
            padding: 1rem 1.5rem;
        }

        .tool-badge {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            background: var(--surface-2);
            border-radius: 8px;
            padding: 0.625rem 0.875rem;
            font-size: 0.825rem;
        }

        .tool-badge .dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            flex-shrink: 0;
        }

        .dot-ok { background: var(--success); box-shadow: 0 0 6px var(--success); }
        .dot-err { background: var(--critical); box-shadow: 0 0 6px var(--critical); }

        .tool-badge .tool-findings {
            margin-left: auto;
            color: var(--text-muted);
            font-size: 0.75rem;
        }

        /* Findings Table */
        .filter-bar {
            padding: 0.75rem 1.5rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
        }

        .filter-btn {
            padding: 0.375rem 0.75rem;
            border-radius: 6px;
            border: 1px solid var(--border);
            background: transparent;
            color: var(--text-muted);
            font-size: 0.75rem;
            cursor: pointer;
            transition: all 0.15s;
        }

        .filter-btn:hover, .filter-btn.active {
            background: var(--accent-glow);
            border-color: var(--accent);
            color: var(--text);
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th {
            text-align: left;
            padding: 0.75rem 1rem;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            border-bottom: 1px solid var(--border);
            position: sticky;
            top: 0;
            background: var(--surface);
        }

        td {
            padding: 0.75rem 1rem;
            border-bottom: 1px solid rgba(71,85,105,0.3);
            font-size: 0.85rem;
            vertical-align: top;
        }

        tr:hover td { background: rgba(129, 140, 248, 0.05); }
        tr.suppressed td { opacity: 0.5; text-decoration: line-through; }

        .severity-badge {
            display: inline-block;
            padding: 0.125rem 0.5rem;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }

        .sev-critical { background: var(--critical-bg); color: var(--critical); }
        .sev-high { background: var(--high-bg); color: var(--high); }
        .sev-medium { background: var(--medium-bg); color: var(--medium); }
        .sev-low { background: var(--low-bg); color: var(--low); }
        .sev-info { background: var(--info-bg); color: var(--info); }

        .file-link { color: var(--accent); word-break: break-all; }
        .finding-title { font-weight: 500; }

        /* Footer */
        .footer {
            text-align: center;
            padding: 2rem;
            color: var(--text-muted);
            font-size: 0.75rem;
        }

        .footer a { color: var(--accent); text-decoration: none; }

        /* No findings */
        .no-findings {
            padding: 3rem;
            text-align: center;
            color: var(--success);
            font-size: 1.25rem;
        }

        .no-findings .icon { font-size: 3rem; margin-bottom: 0.5rem; }

        @media (max-width: 768px) {
            .container { padding: 1rem; }
            .summary-grid { grid-template-columns: repeat(3, 1fr); }
            th:nth-child(4), td:nth-child(4),
            th:nth-child(5), td:nth-child(5) { display: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🛡 DevShield Security Report</h1>
            <div class="meta">
                <span>📁 {{.Result.ProjectPath}}</span>
                <span>⏱ {{formatDuration .Result.ScanDurationSeconds}}</span>
                <span>📅 {{.Generated}}</span>
                <span>🏷 v{{.Result.Version}}</span>
            </div>
        </div>

        <!-- Summary Cards -->
        <div class="summary-grid">
            <div class="summary-card">
                <div class="count count-critical">{{.Result.Summary.Critical}}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card">
                <div class="count count-high">{{.Result.Summary.High}}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card">
                <div class="count count-medium">{{.Result.Summary.Medium}}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card">
                <div class="count count-low">{{.Result.Summary.Low}}</div>
                <div class="label">Low</div>
            </div>
            <div class="summary-card">
                <div class="count count-info">{{.Result.Summary.Info}}</div>
                <div class="label">Info</div>
            </div>
            <div class="summary-card">
                <div class="count count-total">{{.Result.Summary.Total}}</div>
                <div class="label">Total</div>
            </div>
        </div>

        <!-- Tools -->
        <div class="section">
            <div class="section-header">
                <span>🔧 Scanners</span>
                <span style="font-size:0.75rem;color:var(--text-muted);">{{len .Result.ToolsUsed}} tools ran</span>
            </div>
            <div class="tools-grid">
                {{range .Result.ToolsUsed}}
                <div class="tool-badge">
                    <span class="dot {{if .Error}}dot-err{{else}}dot-ok{{end}}"></span>
                    <strong>{{.Name}}</strong>
                    <span style="color:var(--text-muted);font-size:0.75rem;">v{{.Version}}</span>
                    <span class="tool-findings">{{.FindingsCount}} findings</span>
                </div>
                {{end}}
            </div>
        </div>

        <!-- Findings -->
        <div class="section">
            <div class="section-header">
                <span>🔍 Findings</span>
                <span style="font-size:0.75rem;color:var(--text-muted);">{{.Result.Summary.Total}} active</span>
            </div>

            {{if eq .Result.Summary.Total 0}}
            <div class="no-findings">
                <div class="icon">✅</div>
                <div>No security findings detected — your project looks clean!</div>
            </div>
            {{else}}
            <div style="overflow-x:auto;">
                <table>
                    <thead>
                        <tr>
                            <th style="width:90px">Severity</th>
                            <th>Finding</th>
                            <th>File</th>
                            <th>Tool</th>
                            <th>Rule</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range .Result.Findings}}
                        {{if not .Suppressed}}
                        <tr>
                            <td><span class="severity-badge sev-{{.Severity}}">{{upper (toString .Severity)}}</span></td>
                            <td class="finding-title">{{.Title}}</td>
                            <td class="file-link">{{.File}}{{if gt .Line 0}}:{{.Line}}{{end}}</td>
                            <td>{{.Tool}}</td>
                            <td style="color:var(--text-muted);font-size:0.75rem;">{{.RuleID}}</td>
                        </tr>
                        {{end}}
                        {{end}}
                    </tbody>
                </table>
            </div>
            {{end}}
        </div>

        <!-- Footer -->
        <div class="footer">
            Generated by <a href="https://github.com/NIRODH/devshield">DevShield</a> v{{.Result.Version}}<br>
            Open-source DevSecOps platform — privacy-first, no telemetry
        </div>
    </div>

    <script>
        // Severity filter buttons
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                this.classList.toggle('active');
                filterTable();
            });
        });

        function filterTable() {
            const active = [...document.querySelectorAll('.filter-btn.active')].map(b => b.dataset.severity);
            document.querySelectorAll('tbody tr').forEach(row => {
                if (active.length === 0) { row.style.display = ''; return; }
                const badge = row.querySelector('.severity-badge');
                if (badge) {
                    const sev = badge.textContent.trim().toLowerCase();
                    row.style.display = active.includes(sev) ? '' : 'none';
                }
            });
        }
    </script>
</body>
</html>`
