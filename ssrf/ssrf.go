package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"github.com/alphamystic/odin/lib/utils"
	"github.com/alphamystic/odin/lib/handlers"

	"github.com/alphamystic/scanners/payload"
)


type Target struct {
	URL     string            `json:"url"`
	TargetIPn strings					 `json: "targetip"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
}


type SSRFScanner struct {
	Target   *Target
	Payloads *payloads.PayloadLoader
	ByPass []payload.BypassPayload
}

func NewSSRFScanner(target *Target, payloadDir string) *SSRFScanner {
	payloads := &payloads.PayloadLoader{
		Path:payloadDir,
	}
	return &SSRFScanner{
		Target: target,
		Payloads: payloads,
	}
}

func (s *SSRFScanner) Scan() []handlers.Vulnerabilities {
	var results []handlers.Vulnerabilities

	// Walk through all payload files for different bypass types
	filepath.Walk(s.PayloadDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		payloads, _ := loadPayloads(path)
		attackType := handlers.AttackType(strings.TrimSuffix(info.Name(), filepath.Ext(info.Name())))

		for _, payload := range payloads {
			vuln := s.sendPayload(payload, attackType)
			if vuln.Works {
				results = append(results, vuln)
			}
		}
		return nil
	})

	return results
}

func loadPayloads(path string) ([]string, error) {
	data, err := os.ReadFile(path)c
	if err != nil {
		return nil, err
	}
	return strings.Split(string(data), "\n"), nil
}

func (s *SSRFScanner) sendPayload(payload string, attackType handlers.AttackType) handlers.Vulnerabilities {
	body := fmt.Sprintf(`{"imgURL": "%s"}`, payload)
	req, err := http.NewRequest(s.Target.Method, s.Target.URL, bytes.NewBufferString(body))
	if err != nil {
		return emptyVuln(payload, attackType, err.Error())
	}

	for k, v := range s.Target.Headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return emptyVuln(payload, attackType, err.Error())
	}
	defer resp.Body.Close()

	content, _ := ioutil.ReadAll(resp.Body)

	works := strings.Contains(string(content), "root") || resp.StatusCode == 200

	return handlers.Vulnerabilities{
		Trg:           s.Target,
		Name:          Vulnerability("SSRF"),
		Severity:      7,
		Payload:       payload,
		AT:            attackType,
		Works:         works,
		Details:       string(content),
		TimeStamp:     time.Now(),
	}
}

func emptyVuln(payload string, at handlers.AttackType, reason string) handlers.Vulnerabilities {
	return handlers.Vulnerabilities{
		Name:    Vulnerability("SSRF"),
		Payload: payload,
		AT:      at,
		Works:   false,
		Details: fmt.Sprintf("Error: %s", reason),
		TimeStamp: time.Now(),
	}
}
