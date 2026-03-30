package sarif

import (
	"fmt"
	"math"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/sarif"
)

const nucleiTemplatesURL = "https://github.com/projectdiscovery/nuclei-templates"

// Exporter is an exporter for nuclei sarif output format.
type Exporter struct {
	sarif   *sarif.Report
	mutex   *sync.Mutex
	rulemap map[string]*int // contains rule-id && ruleIndex
	rules   []sarif.ReportingDescriptor
	options *Options
}

// Options contains the configuration options for sarif exporter client
type Options struct {
	// File is the file to export found sarif result to
	File string `yaml:"file"`
}

// New creates a new sarif exporter integration client based on options.
func New(options *Options) (*Exporter, error) {
	report := sarif.NewReport()
	exporter := &Exporter{
		sarif:   report,
		mutex:   &sync.Mutex{},
		rules:   []sarif.ReportingDescriptor{},
		rulemap: map[string]*int{},
		options: options,
	}
	return exporter, nil
}

// addToolDetails adds details of static analysis tool (i.e nuclei)
func (exporter *Exporter) addToolDetails() {
	driver := sarif.ToolComponent{
		Name:         "Nuclei",
		Organization: "ProjectDiscovery",
		Product:      "Nuclei",
		ShortDescription: &sarif.MultiformatMessageString{
			Text: "Fast and Customizable Vulnerability Scanner",
		},
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Fast and customizable vulnerability scanner based on simple YAML based DSL",
		},
		FullName:        "Nuclei " + config.Version,
		SemanticVersion: config.Version,
		DownloadUri:     "https://github.com/projectdiscovery/nuclei/releases",
		InformationUri:  "https://github.com/projectdiscovery/nuclei",

		Rules: exporter.rules,
	}
	exporter.sarif.RegisterTool(driver)

	reportLocation := sarif.ArtifactLocation{
		Uri: "file:///" + exporter.options.File,
		Description: &sarif.Message{
			Text: "Nuclei Sarif Report",
		},
	}

	invocation := sarif.Invocation{
		CommandLine:   os.Args[0],
		Arguments:     os.Args[1:],
		ResponseFiles: []sarif.ArtifactLocation{reportLocation},
	}
	exporter.sarif.RegisterToolInvocation(invocation)
}

// getSeverity in terms of sarif
func (exporter *Exporter) getSeverity(severity string) (sarif.Level, string) {
	switch severity {
	case "critical":
		return sarif.Error, "9.4"
	case "high":
		return sarif.Error, "8"
	case "medium":
		return sarif.Note, "5"
	case "low":
		return sarif.Note, "2"
	case "info":
		return sarif.None, "1"
	}

	return sarif.None, "9.5"
}

// helpURI returns the best available URI for the given result event.
// Priority: 1) verified template cloud URL 2) first reference link 3) nuclei-templates repo.
func helpURI(event *output.ResultEvent) string {
	if event.TemplateURL != "" {
		return event.TemplateURL
	}
	if event.Info.Reference != nil {
		for _, ref := range event.Info.Reference.ToSlice() {
			if u, err := url.ParseRequestURI(ref); err == nil && u.Scheme != "" && u.Host != "" {
				return ref
			}
		}
	}
	return nucleiTemplatesURL
}

// fullDescription builds the rule full-description text. When a help URL is
// available it is appended so readers can navigate to further information.
func fullDescription(event *output.ResultEvent, uri string) string {
	base := event.Info.Description
	if uri != nucleiTemplatesURL {
		return base + "\nMore details at\n" + uri + "\n"
	}
	if base == "" {
		return "No description found in template, have a look for the " + event.TemplateID + " template."
	}
	return base
}

// toPascalCase converts a kebab-case template ID (e.g. "fuzzing-params-xss")
// to a PascalCase identifier (e.g. "FuzzingParamsXss") as required by SARIF rule names.
func toPascalCase(id string) string {
	parts := strings.FieldsFunc(id, func(r rune) bool { return r == '-' || r == '_' })
	for i, p := range parts {
		if len(p) > 0 {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, "")
}

// helpText returns remediation guidance for the given result event.
// Falls back to a generic message if no remediation is specified in the template.
func helpText(event *output.ResultEvent) string {
	if event.Info.Remediation != "" {
		return event.Info.Remediation
	}
	return "No remediation guidance is available for " + event.TemplateID + ". See the HelpUri for more information."
}

// Export exports a passed result event to sarif structure
func (exporter *Exporter) Export(event *output.ResultEvent) error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	severity := event.Info.SeverityHolder.Severity.String()
	resultHeader := fmt.Sprintf("%v (%v) found on %v", event.Info.Name, event.TemplateID, event.Host)
	resultLevel, vulnRating := exporter.getSeverity(severity)

	uri := helpURI(event)

	// Extra metadata if generated sarif is uploaded to GitHub security page
	ghMeta := map[string]interface{}{}
	ghMeta["tags"] = []string{"security"}
	ghMeta["security-severity"] = vulnRating

	// rule contain details of template
	rule := sarif.ReportingDescriptor{
		Id:   event.TemplateID,
		Name: toPascalCase(event.TemplateID),
		FullDescription: &sarif.MultiformatMessageString{
			Text: fullDescription(event, uri),
		},
		Help: &sarif.MultiformatMessageString{
			Text: helpText(event),
		},
		HelpUri:    uri,
		Properties: ghMeta,
	}

	// GitHub Uses ShortDescription as title
	if event.Info.Description != "" {
		rule.ShortDescription = &sarif.MultiformatMessageString{
			Text: resultHeader,
		}
	}

	// If rule is added
	ruleIndex := int(math.Max(0, float64(len(exporter.rules)-1)))
	if exporter.rulemap[rule.Id] == nil {
		exporter.rulemap[rule.Id] = &ruleIndex
		exporter.rules = append(exporter.rules, rule)
	} else {
		ruleIndex = *exporter.rulemap[rule.Id]
	}

	// vulnerability target/location
	location := sarif.Location{
		Message: &sarif.Message{
			Text: path.Join(event.Host, event.Path),
		},
		PhysicalLocation: sarif.PhysicalLocation{
			ArtifactLocation: sarif.ArtifactLocation{
				Uri: strings.TrimLeft(event.Path, "/"),
				Description: &sarif.Message{
					Text: path.Join(event.Host, event.Path),
				},
			},
		},
	}

	// vulnerability report/result
	result := &sarif.Result{
		RuleId:    rule.Id,
		RuleIndex: ruleIndex,
		Level:     resultLevel,
		Kind:      sarif.Open,
		Message: &sarif.Message{
			Text: resultHeader,
		},
		Locations: []sarif.Location{location},
	}

	exporter.sarif.RegisterResult(*result)

	return nil

}

// Close Writes data and closes the exporter after operation
func (exporter *Exporter) Close() error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	if len(exporter.rules) == 0 {
		// no output if there are no results
		return nil
	}
	// links results and rules/templates
	exporter.addToolDetails()

	bin, err := exporter.sarif.Export()
	if err != nil {
		return errors.Wrap(err, "failed to generate sarif report")
	}
	if err := os.WriteFile(exporter.options.File, bin, 0644); err != nil {
		return errors.Wrap(err, "failed to create sarif file")
	}

	return nil
}
