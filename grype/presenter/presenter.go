package presenter

import (
	"io"

	"github.com/anchore/grype/grype/match"

	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/scope"

	"github.com/anchore/grype/grype/presenter/cyclonedx"
	"github.com/anchore/grype/grype/presenter/gitlabsast"
	"github.com/anchore/grype/grype/presenter/json"
	"github.com/anchore/grype/grype/presenter/table"
	"github.com/anchore/syft/syft/pkg"
)

// Presenter is the main interface other Presenters need to implement
type Presenter interface {
	Present(io.Writer) error
}

// GetPresenter retrieves a Presenter that matches a CLI option
func GetPresenter(option Option, results match.Matches, catalog *pkg.Catalog, theScope scope.Scope, metadataProvider vulnerability.MetadataProvider, d *distro.Distro) Presenter {
	switch option {
	case JSONPresenter:
		return json.NewPresenter(results, catalog, theScope, metadataProvider)
	case TablePresenter:
		return table.NewPresenter(results, catalog, metadataProvider)
	case CycloneDxPresenter:
		return cyclonedx.NewPresenter(results, catalog, theScope, metadataProvider)
	case GitlabSASTPresenter:
		return gitlabsast.NewPresenter(results, catalog, theScope, metadataProvider, d)
	default:
		return nil
	}
}
