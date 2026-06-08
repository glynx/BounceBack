package wrapper

import (
	"net/http"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHTTPRequestGetIP(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		want       string
	}{
		{
			name: "cloudfront viewer address forwarded with port",
			headers: map[string]string{
				"X-Forwarded-For": "92.209.232.234:54321",
			},
			remoteAddr: "100.81.202.56:12345",
			want:       "92.209.232.234",
		},
		{
			name: "forwarded chain uses first address",
			headers: map[string]string{
				"X-Forwarded-For": " 92.209.232.234 , 198.51.100.1",
			},
			remoteAddr: "100.81.202.56:12345",
			want:       "92.209.232.234",
		},
		{
			name: "ipv6 address with port",
			headers: map[string]string{
				"X-Real-IP": "[2001:db8::1]:54321",
			},
			remoteAddr: "100.81.202.56:12345",
			want:       "2001:db8::1",
		},
		{
			name:       "invalid forwarded address falls back to remote address",
			headers:    map[string]string{"X-Forwarded-For": "invalid"},
			remoteAddr: "100.81.202.56:12345",
			want:       "100.81.202.56",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := &http.Request{
				Header:     make(http.Header),
				RemoteAddr: tt.remoteAddr,
			}
			for name, value := range tt.headers {
				request.Header.Set(name, value)
			}

			entity := &HTTPRequest{Request: request}
			require.Equal(t, netip.MustParseAddr(tt.want), entity.GetIP())
		})
	}
}
