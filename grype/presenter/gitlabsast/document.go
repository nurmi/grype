package gitlabsast

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	syftJson "github.com/anchore/syft/syft/presenter/json"
	"github.com/anchore/syft/syft/scope"
)

// Document represents the JSON document to be presented
type Document struct {
	Version         string           `json:"version"`
	Vulnerabilities []GVulnerability `json:"vulnerabilities"`
	Remediations    []Remediation    `json:"remediations"`
}

type GVulnerability struct {
	CVE         string       `json:"cve"`
	Category    string       `json:"category"`
	Message     string       `json:"message"`
	Description string       `json:"description"`
	Severity    string       `json:"severity"`
	Confidence  string       `json:"confidence"`
	Solution    string       `json:"solution"`
	Scanner     Scanner      `json:"scanner"`
	Location    Location     `json:"location"`
	Identifiers []Identifier `json:"identifiers"`
	Links       []Link       `json:"links"`
}

type Remediation struct {
}

type Package struct {
	Name string `json:"name"`
}

type Dependency struct {
	Package Package `json:"package"`
	Version string  `json:"version"`
}

type Location struct {
	Dependency      Dependency `json:"dependency"`
	OperatingSystem string     `json:"operating_system"`
	Image           string     `json:"image"`
}

type Scanner struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Link struct {
	URL string `json:"url"`
}

type Identifier struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	URL   string `json:"url"`
}

func MakeSeverityMap() (map[string]string, error) {
	// Severity mapping (anchore -> gitlab sast) section
	sevmap := make(map[string]string)
	sevmap["critical"] = string("Critical")
	sevmap["high"] = string("High")
	sevmap["medium"] = string("Medium")
	sevmap["low"] = string("Low")
	sevmap["negligible"] = string("Info")
	sevmap["unknown"] = string("Info")
	return sevmap, nil
}

func MakeScanner() Scanner {
	scanner := Scanner{
		ID:   "anchore-grype",
		Name: "anchore-grype",
	}
	return scanner
}

func MakeGpackage(art syftJson.Artifact) Package {
	gpackage := Package{
		Name: art.Name,
	}
	return gpackage
}

func MakeDependency(gpackage Package, art syftJson.Artifact) Dependency {
	dependency := Dependency{
		Package: gpackage,
		Version: art.Version,
	}
	return dependency
}

func MakeIdentifiers(m match.Match) []Identifier {
	identifier := Identifier{
		Type:  "cve",
		Name:  m.Vulnerability.ID,
		Value: m.Vulnerability.ID,
		URL:   "",
	}

	var identifiers []Identifier
	identifiers = append(identifiers, identifier)

	return identifiers
}

func MakeLinks(metadata *vulnerability.Metadata) ([]Link, string) {
	var mainLink string

	// populate links section of vulnerability record, also set the (one) identifier record with an arbitrary link from set of links.  Improvement would be to use a 'preferred' link or implement logic to use an NVD link if the id is a CVE, redhat link if id is an RHSA, debian link if the artifact is a dpkg, etc.
	links := make([]Link, 0)
	for _, l := range metadata.Links {
		//identifiers[0].URL = l
		mainLink = l
		links = append(links,
			Link{
				URL: l,
			},
		)
	}
	return links, mainLink
}

// TODO investigate this gitlab SAST version/meaning
// TODO - presently, this presenter only supports container image type as there are container image elements in the SAST schema
// we must preallocate the findings to ensure the JSON document does not show "null" when no matches are found
// extract the effected package artifact, and vulnerability / source metadata from the match
// set up and populate the gitlab sast sub-elements for this record
// TODO - see if we can get the discovered distro/version from syft/stereoscope in the future, for container image type
// Set up the gitlab sast final vulnerability record
//var gv GVulnerability
// Finally, append the new record to the list of findings
// Populate the final gitlab sast document with generated data
// TODO investigate populating the remediations section if possible from any fixedIn elements of vulnerability findings
// NewDocument creates and populates a new Document struct, representing the populated JSON document.
func NewDocument(catalog *pkg.Catalog, s scope.Scope, matches match.Matches, metadataProvider vulnerability.MetadataProvider, d *distro.Distro) (Document, error) {
	doc := Document{}
	var errb bool
	sastVersion := "2.3"
	var image *syftJson.Image
	switch src := s.Source.(type) {
	case scope.ImageSource:
		image = syftJson.NewImage(src)
	default:
		return Document{}, fmt.Errorf("unsupported source: %T", src)
	}
	sevmap, err := MakeSeverityMap()
	if err != nil {
		return Document{}, err
	}
	scanner := MakeScanner()
	var findings = make([]GVulnerability, 0)
	for m := range matches.Enumerate() {
		p := catalog.Package(m.Package.ID())
		art, err := syftJson.NewArtifact(p, s)
		if err != nil {
			return Document{}, err
		}
		metadata, err := metadataProvider.GetMetadata(m.Vulnerability.ID, m.Vulnerability.RecordSource)
		if err != nil {
			return Document{}, fmt.Errorf("unable to fetch vuln=%q metadata: %+v", m.Vulnerability.ID, err)
		}
		gpackage := MakeGpackage(art)
		dependency := MakeDependency(gpackage, art)
		operatingSystem := d.Name() + ":" + d.FullVersion()
		location := Location{
			Dependency:      dependency,
			OperatingSystem: operatingSystem,
			Image:           image.Tags[0],
		}
		var identifiers = MakeIdentifiers(m)
		links, mainLink := MakeLinks(metadata)
		identifiers[0].URL = mainLink
		var severity string
		severity, errb = sevmap[strings.ToLower(metadata.Severity)]
		if !errb {
			severity = "Info"
		}
		gv := GVulnerability{
			CVE:         image.Digest + ":" + art.Name + "-" + art.Version + ":" + m.Vulnerability.ID,
			Category:    "container_scanning",
			Message:     m.Vulnerability.ID + " in " + art.Name + "-" + art.Version,
			Description: metadata.Description,
			Severity:    severity,
			Confidence:  "Unknown",
			Solution:    "Unknown",
			Scanner:     scanner,
			Location:    location,
			Identifiers: identifiers,
			Links:       links,
		}
		findings = append(
			findings,
			gv,
		)
	}
	doc.Version = sastVersion
	doc.Vulnerabilities = findings
	doc.Remediations = make([]Remediation, 0)
	return doc, nil
}
