package sbom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/anchore/syft/syft/formats/cyclonedxjson"
	"github.com/anchore/syft/syft/formats/cyclonedxxml"
	"github.com/anchore/syft/syft/formats/spdx22json"
	"github.com/anchore/syft/syft/formats/spdx22tagvalue"
	"github.com/anchore/syft/syft/formats/syftjson"
	"github.com/in-toto/in-toto-golang/in_toto"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
	"github.com/anchore/syft/syft/sbom"
)

// NewSBOMCataloger returns a new SBOM cataloger object loaded from saved SBOM JSON.
func NewSBOMCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/*.syft.json": makeParser(syftjson.Format()),
		"**/bom.json":    makeParser(cyclonedxjson.Format()),
		"**/bom.xml":     makeParser(cyclonedxxml.Format()),
		"**/*.cdx.json":  makeParser(cyclonedxjson.Format()),
		"**/*.cdx.xml":   makeParser(cyclonedxxml.Format()),
		"**/*.spdx.json": makeParser(spdx22json.Format()),
		"**/*.spdx":      makeParser(spdx22tagvalue.Format()),
	}
	return common.NewGenericCataloger(nil, globParsers, "sbom-cataloger")
}

func makeParser(format sbom.Format) func(string, io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	return func(_ string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
		by, err := io.ReadAll(reader)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to read sbom: %w", err)
		}

		var stmt in_toto.Statement
		if err := json.Unmarshal(by, &stmt); err == nil && stmt.Type == in_toto.StatementInTotoV01 {
			by, _ = json.Marshal(stmt.Predicate)
		}

		s, err := format.Decode(bytes.NewReader(by))
		if err != nil {
			return nil, nil, fmt.Errorf("unable to decode sbom: %w", err)
		}

		var packages []*pkg.Package
		for _, p := range s.Artifacts.PackageCatalog.Sorted() {
			x := p // copy
			packages = append(packages, &x)
		}

		return packages, nil, nil
	}
}
