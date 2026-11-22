package openconnect_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	openconnect "github.com/sagernet/sing-openconnect"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

func TestFortinetHTMLLoginFailureRemainsCredentialChallenge(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte("<html>login</html>"))
			return
		}
		_, _ = w.Write([]byte("<html>incorrect password</html>"))
	}))
	defer server.Close()
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Server: server.URL, Flavor: openconnect.FlavorFortinet, Username: "test-user", Password: "wrong-test-password",
		Logger: logger.NOP(), NoUDP: true,
		TLSConfig: openconnect.ClientTLSOptions{Config: &tls.Config{InsecureSkipVerify: true}},
	})
	require.NoError(t, err)
	defer client.Close()
	require.NoError(t, client.Start())
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		changed := client.AuthChallengeUpdated()
		if challenge := client.PendingAuthChallenge(); challenge != nil {
			require.Nil(t, challenge.Browser, "a generic HTML login failure must not be converted into a fabricated SAML URL")
			require.NotNil(t, challenge.Form)
			var passwordField bool
			for _, field := range challenge.Form.Fields {
				passwordField = passwordField || field.Kind == openconnect.AuthFormFieldPassword
			}
			require.True(t, passwordField)
			return
		}
		select {
		case <-changed:
		case <-deadline.C:
			t.Fatal("Fortinet failed login did not publish a credential challenge")
		}
	}
}

func TestFortinetExplicitSAMLRedirectKeepsBrowserChallenge(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/remote/saml/start?realm=unit-test", http.StatusFound)
	}))
	defer server.Close()
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Server: server.URL, Flavor: openconnect.FlavorFortinet, Logger: logger.NOP(), NoUDP: true,
		TLSConfig: openconnect.ClientTLSOptions{Config: &tls.Config{InsecureSkipVerify: true}},
	})
	require.NoError(t, err)
	defer client.Close()
	require.NoError(t, client.Start())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		changed := client.AuthChallengeUpdated()
		if challenge := client.PendingAuthChallenge(); challenge != nil {
			require.NotNil(t, challenge.Browser)
			require.True(t, strings.Contains(challenge.Browser.URL, "/remote/saml/start"))
			require.Nil(t, challenge.Form)
			return
		}
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatal("Fortinet SAML redirect did not publish a browser challenge")
		}
	}
}
