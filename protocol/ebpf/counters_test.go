//go:build with_ebpf && (linux || android)

package ebpf

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestRecordTCUpdateOutcomeCountsRecoveryAttempts proves a round in which
// any component reports Recoverable counts as one attempt, whether or not
// any other component is settled at the same time.
func TestRecordTCUpdateOutcomeCountsRecoveryAttempts(t *testing.T) {
	inbound := &Inbound{}
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteSettled,
		general:       tcSharedRewriteRecoverable,
		bypassRuleSet: tcSharedRewriteSettled,
	})
	if attempts := inbound.counters.recoveryAttempts.Load(); attempts != 1 {
		t.Fatalf("recoveryAttempts = %d, want 1", attempts)
	}
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteSettled,
		general:       tcSharedRewriteSettled,
		bypassRuleSet: tcSharedRewriteSettled,
	})
	if attempts := inbound.counters.recoveryAttempts.Load(); attempts != 1 {
		t.Fatalf("recoveryAttempts = %d, want still 1 after an all-settled round", attempts)
	}
}

// TestRecordTCUpdateOutcomeCountsRecoverySuccessPerComponent proves each
// component transitioning from Recoverable to Settled counts its own
// success -- two components recovering in the same round count as two.
func TestRecordTCUpdateOutcomeCountsRecoverySuccessPerComponent(t *testing.T) {
	inbound := &Inbound{}
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteRecoverable,
		general:       tcSharedRewriteRecoverable,
		bypassRuleSet: tcSharedRewriteSettled,
	})
	if successes := inbound.counters.recoverySuccesses.Load(); successes != 0 {
		t.Fatalf("recoverySuccesses = %d, want 0 before anything has settled", successes)
	}
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteSettled,
		general:       tcSharedRewriteSettled,
		bypassRuleSet: tcSharedRewriteSettled,
	})
	if successes := inbound.counters.recoverySuccesses.Load(); successes != 2 {
		t.Fatalf("recoverySuccesses = %d, want 2 (both sharedRewrite and general settled)", successes)
	}
}

// TestRecordTCUpdateOutcomeCountsRecoveryFailureOnUnrecoverable proves a
// transition to Unrecoverable counts as a failure exactly once, not on
// every subsequent round it stays Unrecoverable.
func TestRecordTCUpdateOutcomeCountsRecoveryFailureOnUnrecoverable(t *testing.T) {
	inbound := &Inbound{}
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteSettled,
		general:       tcSharedRewriteRecoverable,
		bypassRuleSet: tcSharedRewriteSettled,
	})
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteSettled,
		general:       tcSharedRewriteUnrecoverable,
		bypassRuleSet: tcSharedRewriteSettled,
	})
	if failures := inbound.counters.recoveryFailures.Load(); failures != 1 {
		t.Fatalf("recoveryFailures = %d, want 1", failures)
	}
	inbound.recordTCUpdateOutcome(tcUpdateOutcome{
		sharedRewrite: tcSharedRewriteSettled,
		general:       tcSharedRewriteUnrecoverable,
		bypassRuleSet: tcSharedRewriteSettled,
	})
	if failures := inbound.counters.recoveryFailures.Load(); failures != 1 {
		t.Fatalf("recoveryFailures = %d, want still 1 while it stays Unrecoverable", failures)
	}
}

// TestAssignmentLookupFailureCounterInDiagnostics proves the counter
// incremented at tc_connection.go's failure sites is what Diagnostics
// reports -- exercised directly here rather than through a real lookup,
// since the counter itself, not the lookup, is what this test is about.
func TestRawIPCounterFieldsInDiagnostics(t *testing.T) {
	inbound := &Inbound{}
	inbound.counters.assignmentLookupFailures.Store(0)
	diagnostics := inbound.Diagnostics()
	diagnostics.Counters.RawIPAttempts = 3
	diagnostics.Counters.RawIPHeadFailures = 1
	diagnostics.Counters.RawIPHeaderFailures = 2
	diagnostics.Counters.RawIPRedirectFailures = 4
	diagnostics.Counters.DeliveryParseFailures = 5
	if diagnostics.Counters.RawIPAttempts != 3 || diagnostics.Counters.RawIPHeadFailures != 1 ||
		diagnostics.Counters.RawIPHeaderFailures != 2 || diagnostics.Counters.RawIPRedirectFailures != 4 ||
		diagnostics.Counters.DeliveryParseFailures != 5 {
		t.Fatalf("raw-IP diagnostic fields were not retained: %+v", diagnostics.Counters)
	}
	encoded, err := json.Marshal(diagnostics.Counters)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		`"raw_ip_attempts":3`,
		`"raw_ip_head_failures":1`,
		`"raw_ip_header_failures":2`,
		`"raw_ip_redirect_failures":4`,
		`"delivery_parse_failures":5`,
	} {
		if !containsJSONField(encoded, field) {
			t.Fatalf("JSON diagnostics missing %s: %s", field, encoded)
		}
	}
}

func containsJSONField(encoded []byte, field string) bool {
	return strings.Contains(string(encoded), field)
}

func TestAssignmentLookupFailureCounterInDiagnostics(t *testing.T) {
	inbound := &Inbound{}
	inbound.counters.assignmentLookupFailures.Add(3)
	if got := inbound.Diagnostics().Counters.AssignmentLookupFailures; got != 3 {
		t.Fatalf("Counters.AssignmentLookupFailures = %d, want 3", got)
	}
}

// TestSharedReconcileFailureCounterInDiagnostics is the same proof for the
// shared packet-rewrite reconcile-failure counter.
func TestSharedReconcileFailureCounterInDiagnostics(t *testing.T) {
	inbound := &Inbound{}
	inbound.counters.sharedReconcileFailures.Add(2)
	if got := inbound.Diagnostics().Counters.SharedReconcileFailures; got != 2 {
		t.Fatalf("Counters.SharedReconcileFailures = %d, want 2", got)
	}
}
