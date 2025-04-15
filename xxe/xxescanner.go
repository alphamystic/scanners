package xxe

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/alphamystic/odin/lib/utils"
	"github.com/alphamystic/odin/lib/handlers"
)


type Target struct {
	URL string `json:"url"`
	Method string `json:"method"`
	Headers map[string]string `json:"headers"`
}


type XXEScanner struct {
	Target   *handlers.Target
	Payloads []string
	Client   *http.Client
}

func NewXXEScanner(target *Target, payloadFile string) (*XXEScanner, error) {
	file, err := os.ReadFile(payloadFile)
	if err != nil {
		return nil, err
	}
	var payloads []string
	if err := json.Unmarshal(file, &payloads); err != nil {
		return nil, err
	}
	return &XXEScanner{
		Target:   target,
		Payloads: payloads,
		Client:   &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (x *XXEScanner) Scan() []Vulnerabilities {
	var vulns []handlers.Vulnerabilities

	for _, payload := range x.Payloads {
		req, err := http.NewRequest(x.Target.Method, x.Target.URL, bytes.NewBuffer([]byte(payload)))
		if err != nil {
			continue
		}
		for key, val := range x.Target.Headers {
			req.Header.Set(key, val)
		}

		resp, err := x.Client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		works := bytes.Contains(body, []byte("root:")) || bytes.Contains(body, []byte("admin:"))
		vuln := Vulnerabilities{
			Trg:     x.Target,
			Name:    "XXE Injection",
			Severity: 8,
			Target:  x.Target.URL,
			Payload: payload,
			AT:      "XXE",
			Works:   works,
			Details: fmt.Sprintf("Response contains %d bytes", len(body)),
			}
		vuln.Touch()
		vulns = append(vulns, vuln)
	}

	return vulns
}
