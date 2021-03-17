package presenter

import "strings"

const (
	UnknownPresenter Option = iota
	JSONPresenter
	TablePresenter
	CycloneDxPresenter
	GitlabSASTPresenter
)

var optionStr = []string{
	"UnknownPresenter",
	"json",
	"table",
	"cyclonedx",
	"gitlabsast",
}

var Options = []Option{
	JSONPresenter,
	TablePresenter,
	CycloneDxPresenter,
	GitlabSASTPresenter,
}

type Option int

func ParseOption(userStr string) Option {
	switch strings.ToLower(userStr) {
	case strings.ToLower(JSONPresenter.String()):
		return JSONPresenter
	case strings.ToLower(TablePresenter.String()):
		return TablePresenter
	case strings.ToLower(CycloneDxPresenter.String()):
		return CycloneDxPresenter
	case strings.ToLower(GitlabSASTPresenter.String()):
		return GitlabSASTPresenter
	default:
		return UnknownPresenter
	}
}

func (o Option) String() string {
	if int(o) >= len(optionStr) || o < 0 {
		return optionStr[0]
	}

	return optionStr[o]
}
