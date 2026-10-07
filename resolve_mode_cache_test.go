package web3protocol

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestResolveModeFallbackIsNotCached(t *testing.T) {
	for _, fallback := range []string{"empty", "revert"} {
		t.Run(fallback, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request struct {
					ID json.RawMessage `json:"id"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
					return
				}
				calls++
				response := map[string]interface{}{"jsonrpc": "2.0", "id": request.ID}
				if calls == 1 && fallback == "revert" {
					response["error"] = map[string]interface{}{"code": 3, "message": "execution reverted"}
				} else if calls == 1 {
					response["result"] = "0x"
				} else {
					response["result"] = "0x3532313900000000000000000000000000000000000000000000000000000000"
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()
			client := NewClient(&Config{Chains: map[int]ChainConfig{11155111: {RPC: ChainRPCConfig{Url: server.URL}}}})
			url := "web3://0x91921Ddf2924d242Feb6546e8cF9e41b6c077222:11155111/"
			first, err := client.ParseUrl(url, nil)
			if err != nil {
				t.Fatal(err)
			}
			if first.ResolveMode != ResolveModeAuto {
				t.Fatalf("first mode: %v", first.ResolveMode)
			}
			key := ResolveModeCacheKey{11155111, common.HexToAddress("0x91921Ddf2924d242Feb6546e8cF9e41b6c077222")}
			if _, cached := client.ResolveModeCache.Get(key); cached {
				t.Fatal("fallback mode was cached")
			}
			second, err := client.ParseUrl(url, nil)
			if err != nil {
				t.Fatal(err)
			}
			if second.ResolveMode != ResolveModeResourceRequests {
				t.Fatalf("second mode: %v", second.ResolveMode)
			}
			if _, cached := client.ResolveModeCache.Get(key); !cached {
				t.Fatal("explicit mode was not cached")
			}
			if _, err := client.ParseUrl(url, nil); err != nil {
				t.Fatal(err)
			}
			if calls != 2 {
				t.Fatalf("expected 2 RPC calls, got %d", calls)
			}
		})
	}
}
