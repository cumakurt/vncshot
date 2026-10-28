package report

import "time"

// CountExpiringSoon reports how many results carry a peer certificate that
// falls inside the expiry warning window.
//
// The count is computed against the caller's clock (now) at report time, not
// against a stored scan-time snapshot, so the number a report or notification
// shows describes the certificates the reader is looking at.
//
// A result counts when its TLS session was established (Certificate non-nil),
// the peer certificate records its end of validity (NotAfter non-zero) and
// the remaining validity NotAfter.Sub(now) lies in the closed interval
// [0, within]:
//
//   - remaining >= 0: the certificate is still valid at now. A certificate
//     that has already expired is reported by the expired counters instead
//     and is deliberately not "expiring soon".
//   - remaining <= within: the certificate expires inside the window. The
//     boundary is inclusive, so a certificate expiring exactly within ahead
//     of now does count.
//
// A non-positive within means no warning window was configured and the count
// is 0.
func CountExpiringSoon(results []Result, now time.Time, within time.Duration) int {
	if within <= 0 {
		return 0
	}
	count := 0
	for _, r := range results {
		certificate := r.Certificate
		if certificate == nil || certificate.NotAfter.IsZero() {
			continue
		}
		remaining := certificate.NotAfter.Sub(now)
		if remaining >= 0 && remaining <= within {
			count++
		}
	}
	return count
}

// MarkExpiringSoon flags every result whose peer certificate falls inside the
// expiry warning window and returns how many were flagged. The flags use the
// same closed-interval rule as CountExpiringSoon, so a report's expires-soon
// markers and its expiring_soon counter always agree. It mutates the results
// in place; call it once per scan, before the results are rendered or sent
// anywhere. A non-positive within means no window was configured and marks
// nothing.
func MarkExpiringSoon(results []Result, now time.Time, within time.Duration) int {
	if within <= 0 {
		return 0
	}
	count := 0
	for i := range results {
		certificate := results[i].Certificate
		if certificate == nil || certificate.NotAfter.IsZero() {
			continue
		}
		remaining := certificate.NotAfter.Sub(now)
		if remaining >= 0 && remaining <= within {
			results[i].ExpiresSoon = true
			count++
		}
	}
	return count
}
