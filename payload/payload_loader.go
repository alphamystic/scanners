package payloads

import (
	"fmt"
	"net"
	"bufio"
	"strconv"
	"strings"
	"encoding/json"
	"encoding/binary"
)

type BypassPayload struct {
	Payload string
	EncodedPayload string
}

type PayloadLoader struct {
	Payloads []string
	Path string
}

func (pl *PayloadLoader) LoadPayloads() error {
	file, err := os.Open(pl.Path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var payloads []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		payloads = append(payloads, scanner.Text())
	}
	pl.Payloads = payloads
	return scanner.Err()
}

// IPPatterns holds various encoded representations of an IP address
type IPPatterns struct {
	InputIP        string `json:"input_ip"`
	NormalizedIP   string `json:"normalized_ip"`
	Decimal        string `json:"decimal"`
	Hex            string `json:"hex"`
	Octal          string `json:"octal"`
}

// EncodeIPPatterns encodes an IP into various representations
func EncodeIPPatterns(input string) (*IPPatterns, error) {
	toDecimal := func(ip net.IP) string {
		ip = ip.To4()
		if ip == nil {
			return ""
		}
		return fmt.Sprintf("%d", binary.BigEndian.Uint32(ip))
	}

	toHex := func(ip net.IP) string {
		ip = ip.To4()
		if ip == nil {
			return ""
		}
		return fmt.Sprintf("0x%02x%02x%02x%02x", ip[0], ip[1], ip[2], ip[3])
	}

	toOctal := func(ip net.IP) string {
		ip = ip.To4()
		if ip == nil {
			return ""
		}
		return fmt.Sprintf("0%o.0%o.0%o.0%o", ip[0], ip[1], ip[2], ip[3])
	}

	toOverflowed := func(ipStr string) (string, error) {
		parts := strings.Split(ipStr, ".")
		if len(parts) > 4 {
			return "", fmt.Errorf("invalid IP format")
		}

		ipNums := make([]int, 4)
		for i := 0; i < 4; i++ {
			if i < len(parts) {
				val, err := strconv.Atoi(parts[i])
				if err != nil {
					return "", err
				}
				ipNums[i] = val
			} else {
				ipNums[i] = 0
			}
		}

		// Normalize overflowing values
		for i := len(parts) - 1; i < 3; i++ {
			ipNums[i+1] += ipNums[i] / 256
			ipNums[i] = ipNums[i] % 256
		}
		for i := 0; i < 4; i++ {
			ipNums[i] = ipNums[i] % 256
		}

		return fmt.Sprintf("%d.%d.%d.%d", ipNums[0], ipNums[1], ipNums[2], ipNums[3]), nil
	}

	overflowedIP, err := toOverflowed(input)
	if err != nil {
		return nil, err
	}

	parsedIP := net.ParseIP(overflowedIP)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP after normalization: %s", overflowedIP)
	}

	return &IPPatterns{
		InputIP:      input,
		NormalizedIP: overflowedIP,
		Decimal:      toDecimal(parsedIP),
		Hex:          toHex(parsedIP),
		Octal:        toOctal(parsedIP),
	}, nil
}
