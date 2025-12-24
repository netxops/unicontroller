package dptech

import (
	"github.com/netxops/utils/text"
	"strings"
)

func parseSection(config, regex, name string) string {
	sectionRegexMap := map[string]string{
		"regex": regex,
		"name":  "section",
		"flags": "m",
		"pcre":  "true",
	}

	sectionResult, err := text.SplitterProcessOneTime(sectionRegexMap, config)
	if err != nil {
		panic(err)
	}

	var sections []string
	for it := sectionResult.Iterator(); it.HasNext(); {
		_, _, sectionMap := it.Next()
		sections = append(sections, sectionMap[name])
	}

	return strings.Join(sections, "\n")

}
