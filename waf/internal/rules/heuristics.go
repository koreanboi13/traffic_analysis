package rules

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

var specialChars = `'"();=<>{}[]\/-*|&%$#@!`

// specialCharRatio returns the ratio of special characters to total rune count.
func specialCharRatio(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	count := 0
	for _, c := range s {
		if strings.ContainsRune(specialChars, c) {
			count++
		}
	}
	return float64(count) / float64(utf8.RuneCountInString(s))
}

var htmlTagPattern = regexp.MustCompile(`<[a-zA-Z][a-zA-Z0-9]*(?:\s[^>]*)?>`)

// containsHTMLTags returns true if the string contains HTML-like tags.
func containsHTMLTags(s string) bool {
	return htmlTagPattern.MatchString(s)
}

var sqlHeuristicPattern = regexp.MustCompile(`(?i)['"].*?(?:or|and|union|select)\b|[=<>!]\s*['"\d]`)

// hasSQLiHeuristic returns true if the string contains suspicious SQL-like sequences.
func hasSQLiHeuristic(s string) bool {
	return sqlHeuristicPattern.MatchString(s)
}
