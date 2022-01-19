package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/thanos-io/thanos/pkg/testutil"
)

type loginApprole struct {
	SecretID string `json:"secret_id"`
	RoleID   string `json:"role_id"`
}

func TestNewVaultClient(t *testing.T) {
	var (
		secretID  string = "secretIDexample"
		roleID    string = "roleIDexample"
		prodToken string = "secretProdTokensss"
		devToken  string = "secretDevToken"
	)

	logger := logrus.New()
	srv := &http.Server{}
	t.Cleanup(func() {
		_ = srv.Shutdown(context.TODO())
	})
	smux := mux.NewRouter()
	smux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(500)
			_, _ = w.Write([]byte(fmt.Sprintf("error occurred: %s", err.Error())))
			return
		}

		var credentials loginApprole
		err = json.Unmarshal(body, &credentials)
		if err != nil {
			w.WriteHeader(500)
			_, _ = w.Write([]byte(fmt.Sprintf("error occurred: %s", err.Error())))
			return
		}

		content, err := json.Marshal(map[string]interface{}{"auth": map[string]string{"client_token": prodToken}})
		if err != nil {
			w.WriteHeader(500)
			_, _ = w.Write([]byte(fmt.Sprintf("error occurred: %s", err.Error())))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if credentials.RoleID == roleID && credentials.SecretID == secretID {
			_, _ = w.Write([]byte(content))
		} else {
			w.WriteHeader(403)
			_, _ = w.Write([]byte("access denied"))
		}
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	testutil.Ok(t, err)

	srv.Handler = smux

	srv.Addr = ":0"
	go func() { _ = srv.Serve(listener) }()

	os.Setenv("VAULT_ADDR", "http://"+listener.Addr().String())
	os.Setenv("VAULT_DEV_ROOT_TOKEN_ID", devToken)

	for _, tcase := range []struct {
		tcaseName     string
		env           string
		expectedToken string
	}{
		{
			tcaseName:     "prod environment, token received by approle auth method",
			env:           "prod",
			expectedToken: prodToken,
		},
		{
			tcaseName:     "dev environment, token from env variable",
			env:           "dev",
			expectedToken: devToken,
		},
	} {
		t.Run(tcase.tcaseName, func(t *testing.T) {
			client, err := NewVaultClient(roleID, secretID, tcase.env, "testPrefix", logger)
			testutil.Ok(t, err)
			testutil.Equals(t, tcase.expectedToken, client.client.Token())
		})
	}
}
