package model

import "testing"

func TestExitCodes(t *testing.T) {
	tests := []struct {
		findings []Finding
		want     int
	}{
		{nil, 0},
		{[]Finding{{Severity: SeverityLow}}, 1},
		{[]Finding{{Severity: SeverityHigh}}, 2},
	}
	for _, test := range tests {
		report := Report{Summary: Summarize(test.findings)}
		if got := ExitCode(report); got != test.want {
			t.Fatalf("expected %d, got %d", test.want, got)
		}
	}
}
