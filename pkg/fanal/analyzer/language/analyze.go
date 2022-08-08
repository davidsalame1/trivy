package language

import (
	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Analyze(fileType, filePath string, r dio.ReadSeekerAt, parser godeptypes.Parser) (*analyzer.AnalysisResult, error) {
	parsedLibs, parsedDependencies, err := parser.Parse(r)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse %s: %w", filePath, err)
	}

	// The file path of each library should be empty in case of dependency list such as lock file
	// since they all will be the same path.
	return ToAnalysisResult(fileType, filePath, "", parsedLibs, parsedDependencies), nil
}

func ToAnalysisResult(fileType, filePath, libFilePath string, libs []godeptypes.Library, depGraph []godeptypes.Dependency) *analyzer.AnalysisResult {
	if len(libs) == 0 {
		return nil
	}

	deps := make(map[string][]string)
	for _, dep := range depGraph {
		deps[dep.ID] = dep.DependsOn
	}

	var pkgs []types.Package
	for _, lib := range libs {
		var licenses []string
		if lib.License != "" {
			licenses = []string{lib.License}
		}
		pkgs = append(pkgs, types.Package{
			ID:                 lib.ID,
			Name:               lib.Name,
			Version:            lib.Version,
			FilePath:           libFilePath,
			Indirect:           lib.Indirect,
			Licenses:           licenses,
			DependsOn:          deps[lib.ID],
			ExternalReferences: convertExternalReferences(lib.ExternalReferences),
		})
	}
	apps := []types.Application{{
		Type:      fileType,
		FilePath:  filePath,
		Libraries: pkgs,
	}}

	return &analyzer.AnalysisResult{Applications: apps}
}

func convertExternalReferences(refs []godeptypes.ExternalRef) []types.ExternalRef {
	var externalReferences []types.ExternalRef
	for _, ref := range refs {
		externalReferences = append(externalReferences, types.ExternalRef{
			Type: convertType(ref.Type),
			Url:  ref.URL,
		})
	}
	return externalReferences
}

func convertType(t godeptypes.RefType) types.RefType {
	switch t {
	case godeptypes.RefWebsite:
		return types.RefWebsite
	case godeptypes.RefLicense:
		return types.RefLicense
	case godeptypes.RefVCS:
		return types.RefVCS
	case godeptypes.RefIssueTracker:
		return types.RefIssueTracker
	case godeptypes.RefOther:
		return types.RefOther
	default:
		return types.RefOther
	}
}
