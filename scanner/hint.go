package scanner

import "strings"

// productNameHints maps lower-case desktop-name substrings to a product
// hint. The list is checked top to bottom, so more specific product names
// come before the generic tokens they could collide with. Tokens are plain
// substrings of the desktop name the server volunteered in ServerInit; the
// scanner never sends anything to elicit them.
//
// This is a triage hint, not identification: desktop names are free-form
// strings and can be spoofed, renamed or simply misleading.
var productNameHints = []struct {
	token string
	hint  string
}{
	{"ultravnc", "UltraVNC"},
	{"tigervnc", "TigerVNC"},
	{"tightvnc", "TightVNC"},
	{"realvnc", "RealVNC"},
	{"x11vnc", "x11vnc"},
	{"librevnc", "LibreVNC"},
	{"novnc", "noVNC"},
	{"vino", "Vino"},
	{"qemu", "QEMU"},
	{"kvm", "KVM"},
}

// productHint returns a best-effort triage hint for a probed server from
// data it already volunteered: the RFB banner version and the ServerInit
// desktop name. It is a heuristic, never an active probe, and it is empty
// when nothing unambiguous is known. Consumers must treat it as a lead, not
// as a verified product identification.
func productHint(rfbVersion, serverName string) string {
	if hint := productNameHint(serverName); hint != "" {
		return hint
	}
	return rfbVersionHint(rfbVersion)
}

// productNameHint matches the desktop name against known product strings,
// case-insensitively. The first match wins.
func productNameHint(serverName string) string {
	if serverName == "" {
		return ""
	}
	lower := strings.ToLower(serverName)
	for _, h := range productNameHints {
		if strings.Contains(lower, h.token) {
			return h.hint
		}
	}
	return ""
}

// rfbVersionHint derives a coarse hint from the server's advertised RFB
// banner version. Only patterns the protocol literature ties to a clear era
// are hinted. RFB 3.7 and 3.8 banners are emitted by too many unrelated
// products (TigerVNC, QEMU, RealVNC, TightVNC 2.x, ...) to say anything
// unambiguous, so they yield "".
func rfbVersionHint(version string) string {
	switch version {
	case "3.3":
		return "legacy RFB 3.3 (older or embedded stack)"
	default:
		return ""
	}
}
