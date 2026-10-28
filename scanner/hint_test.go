package scanner

import "testing"

func TestProductHint(t *testing.T) {
	tests := []struct {
		name       string
		rfbVersion string
		serverName string
		want       string
	}{
		{name: "tigervnc name", rfbVersion: "3.8", serverName: "lab-pc (TigerVNC)", want: "TigerVNC"},
		{name: "realvnc name", rfbVersion: "4.1", serverName: "RealVNC Server", want: "RealVNC"},
		{name: "ultravnc name", rfbVersion: "3.8", serverName: "ULTRAVNC-WS01", want: "UltraVNC"},
		{name: "tightvnc name", rfbVersion: "3.8", serverName: "tightvncserver", want: "TightVNC"},
		{name: "x11vnc name", rfbVersion: "3.8", serverName: "x11vnc: :0", want: "x11vnc"},
		{name: "vino name", rfbVersion: "3.7", serverName: "GNOME Desktop, vino", want: "Vino"},
		{name: "qemu name", rfbVersion: "3.8", serverName: "QEMU (vm-14)", want: "QEMU"},
		{name: "kvm name", rfbVersion: "3.8", serverName: "Host KVM console", want: "KVM"},
		{name: "novnc name", rfbVersion: "3.8", serverName: "noVNC :1", want: "noVNC"},
		{name: "librevnc name", rfbVersion: "3.8", serverName: "LibreVNC session", want: "LibreVNC"},
		{name: "name match wins over version hint", rfbVersion: "3.3", serverName: "TigerVNC", want: "TigerVNC"},
		{name: "legacy 3.3 banner", rfbVersion: "3.3", serverName: "ref-plain-33", want: "legacy RFB 3.3 (older or embedded stack)"},
		{name: "modern banner is not attributed", rfbVersion: "3.8", serverName: "finance-desktop", want: ""},
		{name: "3.7 banner is not attributed", rfbVersion: "3.7", serverName: "", want: ""},
		{name: "empty inputs", rfbVersion: "", serverName: "", want: ""},
		{name: "unknown name and banner", rfbVersion: "3.8", serverName: "guard-01", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := productHint(tt.rfbVersion, tt.serverName); got != tt.want {
				t.Errorf("productHint(%q, %q) = %q, want %q", tt.rfbVersion, tt.serverName, got, tt.want)
			}
		})
	}
}
