package nvdtracker

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/wolfi-dev/wolfictl/pkg/index"
	"github.com/wolfi-dev/wolfictl/pkg/vuln"
)

var _ vuln.Searcher = (*NVDTracker)(nil)

type NVDTracker struct {
}

func (t *NVDTracker) VulnerabilitiesForPackage(name string) ([]vuln.Match, error) {
	return nil, errors.New("unimplemented")
}

type op string

var (
	opEQ  op = "=="
	opGTE op = ">="
	opGT  op = ">"
	opLTE op = "<="
	opLT  op = "<"
)

func (t *NVDTracker) AllVulnerabilities() (map[string][]vuln.Match, error) {
	f, err := fetchNVD()
	if err != nil {
		return nil, err
	}
	for _, cve := range f.CVEItems {
		for _, n := range cve.Configurations.Nodes {
			for _, m := range n.CpeMatch {
				cpe := m.Cpe23Uri
				parts := strings.Split(cpe, ":")
				vendor := parts[3]
				product := parts[4]
				version := parts[5]

				var start, end string
				var startop, endop op = opEQ, opEQ
				if m.VersionStartIncluding != "" {
					start = m.VersionStartExcluding
					startop = opGTE
				}
				if m.VersionStartExcluding != "" {
					start = m.VersionStartExcluding
					startop = opGT
				}
				if m.VersionEndIncluding != "" {
					end = m.VersionEndIncluding
					endop = opLTE
				}
				if m.VersionEndExcluding != "" {
					end = m.VersionEndExcluding
					endop = opLT
				}
			}
		}
	}

	idx, err := index.Index("x86_64", "https://packages.wolfi.dev/os") // TODO
	if err != nil {
		return nil, err
	}

	for _, p := range idx.Packages {

	}

	return nil, errors.New("unimplemented")
}

func fetchNVD() (*nvdFeed, error) {
	resp, err := http.Get("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz")
	if err != nil {
		return nil, err
	}
	// TODO: check if 200
	defer resp.Body.Close()
	r, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	var feed nvdFeed
	if err := json.NewDecoder(r).Decode(&feed); err != nil {
		return nil, err
	}
}

type nvdFeed struct {
	CVEItems []struct {
		CVE struct {
			CVEDataMeta struct {
				ID       string `json:"ID"`
				ASSIGNER string `json:"ASSIGNER"`
			} `json:"CVE_data_meta"`
			Description struct {
				DescriptionData []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description_data"`
			} `json:"description"`
		} `json:"cve"`
		Configurations struct {
			CVEDataVersion string `json:"CVE_data_version"`
			Nodes          []struct {
				Operator string        `json:"operator"`
				Children []interface{} `json:"children"`
				CpeMatch []struct {
					Vulnerable            bool          `json:"vulnerable"`
					Cpe23Uri              string        `json:"cpe23Uri"`
					CpeName               []interface{} `json:"cpe_name"`
					VersionStartIncluding string        `json:"versionStartIncluding"`
					VersionStartExcluding string        `json:"versionStartExcluding"`
					VersionEndIncluding   string        `json:"versionEndIncluding"`
					VersionEndExcluding   string        `json:"versionEndExcluding"`
				} `json:"cpe_match"`
			} `json:"nodes"`
		} `json:"configurations"`
		PublishedDate    string `json:"publishedDate"`
		LastModifiedDate string `json:"lastModifiedDate"`
	} `json:"CVE_Items"`
}
