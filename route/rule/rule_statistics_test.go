package rule

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAbstractRuleStatistics(t *testing.T) {
	t.Parallel()
	var rule abstractRule

	require.Zero(t, rule.HitCount())
	require.Zero(t, rule.MissCount())
	require.True(t, rule.HitAt().Equal(time.Unix(0, 0)))
	require.True(t, rule.MissAt().Equal(time.Unix(0, 0)))

	before := time.Now()
	rule.Hit()
	rule.Hit()
	rule.Miss()

	require.EqualValues(t, 2, rule.HitCount())
	require.EqualValues(t, 1, rule.MissCount())
	require.False(t, rule.HitAt().Before(before))
	require.False(t, rule.MissAt().Before(before))

	rule.SetDisabled(true)
	require.True(t, rule.Disabled())
	rule.SetDisabled(false)
	require.False(t, rule.Disabled())
}
