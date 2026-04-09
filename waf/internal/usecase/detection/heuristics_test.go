package detection

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSpecialCharRatio_HighForSQLi(t *testing.T) {
	ratio := specialCharRatio("' OR 1=1--")
	assert.Greater(t, ratio, 0.3)
}

func TestSpecialCharRatio_LowForNormal(t *testing.T) {
	ratio := specialCharRatio("normal text")
	assert.Less(t, ratio, 0.1)
}

func TestSpecialCharRatio_EmptyString(t *testing.T) {
	ratio := specialCharRatio("")
	assert.Equal(t, 0.0, ratio)
}

func TestContainsHTMLTags_True(t *testing.T) {
	assert.True(t, containsHTMLTags("<div>test</div>"))
}

func TestContainsHTMLTags_ScriptTag(t *testing.T) {
	assert.True(t, containsHTMLTags("<script>alert(1)</script>"))
}

func TestContainsHTMLTags_False(t *testing.T) {
	assert.False(t, containsHTMLTags("plain text"))
}

func TestContainsHTMLTags_MathExpression(t *testing.T) {
	assert.False(t, containsHTMLTags("1 < 2 and 3 > 1"))
}

func TestHasSQLiHeuristic_True(t *testing.T) {
	assert.True(t, hasSQLiHeuristic("' OR 1=1"))
}

func TestHasSQLiHeuristic_UnionSelect(t *testing.T) {
	assert.True(t, hasSQLiHeuristic("' union select"))
}

func TestHasSQLiHeuristic_False(t *testing.T) {
	assert.False(t, hasSQLiHeuristic("normal search query"))
}
