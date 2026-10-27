package report

import "strings"

// certificateDateLayout is the compact UTC date used wherever a certificate
// validity boundary is shown without a time of day.
const certificateDateLayout = "2006-01-02"

// certificateFingerprintLimit caps the rendered digest. A SHA-256 fingerprint
// in colon notation is 95 characters, so real values pass through unchanged;
// the cap only guards against malformed or concatenated values breaking the
// report layout.
const certificateFingerprintLimit = 95

// certificateTag is one labelled badge rendered next to a certificate. Class
// carries the CSS classes used by the HTML report; the PDF maps the same value
// to its palette.
type certificateTag struct {
	Label string
	Class string
}

// certificateStateLabel returns the single trust state used in the compact
// endpoint table. A self-signed, unverifiable certificate is the normal case
// on VNC appliances, so it is described as evidence rather than as a failure.
func certificateStateLabel(c *Certificate) string {
	switch {
	case c == nil:
		return ""
	case c.Expired:
		return "expired"
	case c.SelfSigned:
		return "self-signed"
	case c.Verified:
		return "verified"
	default:
		return "untrusted"
	}
}

// certificateStateClass maps a certificate state to the HTML badge style.
func certificateStateClass(c *Certificate) string {
	switch {
	case c == nil:
		return ""
	case c.Expired:
		return "tag danger"
	case c.SelfSigned:
		return "tag hot"
	case c.Verified:
		return "tag ok"
	default:
		return "tag hot"
	}
}

// certificateTags lists every trust marker that applies to c. Unlike
// certificateStateLabel it keeps all applicable markers, so a self-signed
// certificate that has also expired shows both.
func certificateTags(c *Certificate) []certificateTag {
	if c == nil {
		return nil
	}
	tags := make([]certificateTag, 0, 3)
	if c.SelfSigned {
		tags = append(tags, certificateTag{"self-signed", "tag hot"})
	}
	if c.Expired {
		tags = append(tags, certificateTag{"expired", "tag danger"})
	}
	if c.Verified {
		tags = append(tags, certificateTag{"verified", "tag ok"})
	} else if !c.SelfSigned {
		// An unverified chain that is not self-signed is genuinely
		// untrusted; a self-signed appliance certificate is already
		// described by its own marker.
		tags = append(tags, certificateTag{"untrusted", "tag hot"})
	}
	return tags
}

// certificateValidityLine returns the compact trailing note used next to the
// state badge, for example "expires 2027-03-04". An expired certificate
// already carries the expired marker, so no duplicate date is appended.
func certificateValidityLine(c *Certificate) string {
	if c == nil || c.Expired || c.NotAfter.IsZero() {
		return ""
	}
	return "expires " + c.NotAfter.UTC().Format(certificateDateLayout)
}

// certificateWindow renders the full NotBefore → NotAfter window for the
// certificate section. Missing boundaries are shown as a dash.
func certificateWindow(c *Certificate) string {
	if c == nil {
		return "-"
	}
	from := "-"
	if !c.NotBefore.IsZero() {
		from = c.NotBefore.UTC().Format(certificateDateLayout)
	}
	to := "-"
	if !c.NotAfter.IsZero() {
		to = c.NotAfter.UTC().Format(certificateDateLayout)
	}
	return from + " → " + to
}

// certificateFieldValue trims a certificate attribute and substitutes a dash
// so the definition lists never render an empty value.
func certificateFieldValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}

// certificateFingerprint returns the display form of the digest, capped so an
// overlong value cannot break the layout.
func certificateFingerprint(c *Certificate) string {
	if c == nil {
		return ""
	}
	fingerprint := strings.TrimSpace(c.Fingerprint)
	runes := []rune(fingerprint)
	if len(runes) <= certificateFingerprintLimit {
		return fingerprint
	}
	return string(runes[:certificateFingerprintLimit-3]) + "..."
}

// certificateResults selects the results that carry peer certificate evidence,
// preserving scan order.
func certificateResults(results []Result) []Result {
	var certified []Result
	for _, r := range results {
		if r.Certificate != nil {
			certified = append(certified, r)
		}
	}
	return certified
}
