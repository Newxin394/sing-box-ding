package group

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestURLTestMemberHealthBackoff(t *testing.T) {
	interval := time.Minute
	var health urlTestMemberHealth
	require.Equal(t, interval, health.backoff(interval))

	health.failures = 2
	require.Equal(t, 2*interval, health.backoff(interval))
	health.failures = 3
	require.Equal(t, 4*interval, health.backoff(interval))
	health.failures = urlTestMaxFailureBackoff
	require.Equal(t, urlTestMaxFailureBackoff*interval, health.backoff(interval))
}

func TestURLTestDialFailuresThresholdAndReset(t *testing.T) {
	var failures urlTestDialFailures
	for i := 0; i < urlTestDialFailureThreshold-1; i++ {
		require.False(t, failures.failure("node", time.Minute))
	}
	require.True(t, failures.failure("node", time.Minute))
	require.False(t, failures.failure("node", time.Minute))
	require.True(t, failures.excessive("node"))

	failures.release()
	failures.success("node")
	require.False(t, failures.excessive("node"))

	failures.failure("node", time.Minute)
	failures.reset()
	require.False(t, failures.excessive("node"))
}
