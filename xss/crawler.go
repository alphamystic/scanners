package xss

import (
	"io"
	"fmt"
	"sync"
	"regexp"
	"strings"
	"net/url"
	"net/http"
	"io/ioutil"
	"compress/gzip"
	"encoding/json"

	"golang.org/x/net/html"
	"github.com/alphamystic/odin/lib/utils"
)
// Structs
type Target struct {
	Input string // can be URL or IP
	IsIP  bool
}

type InjectionPoint struct {
	URL         string
	Method      string
	ParamName   string
	ParamValue  string
	Context     string // form, query, script, etc.
	FormAction  string
	InputType   string
	Suspicious  bool
	Description string
	Headers     http.Header
}

type ClientContext struct {
	Client  *http.Client
	Headers http.Header
}

// Global vars
var (
	visited     = make(map[string]bool)
	mu          sync.Mutex
	wg          sync.WaitGroup
	baseDomain  string
	results     []InjectionPoint
	patterns    = []*regexp.Regexp{
		regexp.MustCompile(`document\\.write\()`),
		regexp.MustCompile(`innerHTML\\s*=`),
		regexp.MustCompile(`outerHTML\\s*=`),
		regexp.MustCompile(`eval\()`),
		regexp.MustCompile(`Function\((.*?)\)`),
		regexp.MustCompile(`setTimeout\([^,]+,`),
		regexp.MustCompile(`setInterval\([^,]+,`),
		regexp.MustCompile(`location\\.href\\s*=`),
		regexp.MustCompile(`document\\.location\\s*=`),
		regexp.MustCompile(`window\\.location\\s*=`),
		regexp.MustCompile(`document\\.cookie\\s*=`),
		regexp.MustCompile(`window\\.open\\s*\(`),
		regexp.MustCompile(`on[a-zA-Z]+\\s*=\\s*`),
		regexp.MustCompile(`\\.html\(`),
		regexp.MustCompile(`\\{\\{.*?\\}\\}`),
		regexp.MustCompile(`href\\s*=\\s*\"javascript:`),
		regexp.MustCompile(`<img[^>]+onerror\\s*=\\s*`),
		regexp.MustCompile(`fetch\\s*\(`),
		regexp.MustCompile(`XMLHttpRequest`),
		regexp.MustCompile(`setAttribute\\(\\\"on[a-z]+`),
		regexp.MustCompile(`srcdoc=`),
		regexp.MustCompile(`data:`),
		regexp.MustCompile(`base64,`),
	}
	defaultClient = &http.Client{}
	clients       = make(map[string]*ClientContext)
)

// Main entry
func StartScan(target Target) {
	u, err := url.Parse(target.Input)
	if err != nil {
		panic(err)
	}
	baseDomain = u.Host
	clients[baseDomain] = &ClientContext{Client: defaultClient, Headers: http.Header{}}

	ctxKey := baseDomain
	if target.IsIP {
		ctxKey = target.Input
	}

	wg.Add(1)
	go crawl(target.Input, ctxKey)
	wg.Wait()

	output, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(output))
}

// Crawler
func crawl(link string, ctxKey string) {
	defer wg.Done()

	if !isWithinDomain(link) {
		return
	}

	mu.Lock()
	if visited[link] {
		mu.Unlock()
		return
	}
	visited[link] = true
	mu.Unlock()

	utils.PrintTextInASpecificColor("blue",fmt.Sprintf("Crawling: %s\n", link))
	clientCtx := clients[ctxKey]
	resp, err := clientCtx.Client.Get(link)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	u, _ := url.Parse(link)
	newHost := u.Host
	if _, exists := clients[newHost]; !exists {
		clients[newHost] = &ClientContext{
			Client:  &http.Client{},
			Headers: resp.Header,
		}
	}

	body := readResponse(resp)
	doc, err := html.Parse(body)
	if err != nil {
		return
	}

	handleHTML(link, doc)
}

func readResponse(resp *http.Response) io.Reader {
	var reader io.Reader = resp.Body
	if strings.Contains(resp.Header.Get("Content-Encoding"), "gzip") {
		gzReader, err := gzip.NewReader(resp.Body)
		if err == nil {
			reader = gzReader
		}
	}
	return reader
}

func isWithinDomain(link string) bool {
	u, err := url.Parse(link)
	if err != nil {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	if ip != nil {
		return true
	}
	return strings.HasSuffix(u.Hostname(), baseDomain)
}

// HTML Handler
func handleHTML(baseURL string, n *html.Node) {
	if n.Type == html.ElementNode {
		switch n.Data {
		case "a":
			handleAnchor(baseURL, n)
		case "form":
			handleForm(baseURL, n)
		case "script":
			handleScript(baseURL, n)
		case "input":
			handleInput(baseURL, n)
		case "img":
			handleImage(baseURL, n)
		case "meta":
			handleMeta(baseURL, n)
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		handleHTML(baseURL, c)
	}
}

func handleAnchor(baseURL string, n *html.Node) {
	for _, attr := range n.Attr {
		if attr.Key == "href" {
			link := resolveURL(baseURL, attr.Val)
			host := getHost(link)
			if isWithinDomain(link) {
				wg.Add(1)
				go crawl(link, host)
			}
			if strings.Contains(link, "?") {
				addInjectionPoint(link, "GET", "query", true, "Query string parameter", nil)
			}
			if strings.HasPrefix(strings.ToLower(attr.Val), "javascript:") {
				addInjectionPoint(baseURL, "DOM", "anchor-js", true, "javascript: URI in anchor href", nil)
			}
		}
	}
}

func handleForm(baseURL string, n *html.Node) {
	action := baseURL
	method := "GET"
	for _, attr := range n.Attr {
		if attr.Key == "action" {
			action = resolveURL(baseURL, attr.Val)
		}
		if attr.Key == "method" {
			method = strings.ToUpper(attr.Val)
		}
	}
	addInjectionPoint(action, method, "form", false, "Form submission detected", nil)
}

func handleInput(baseURL string, n *html.Node) {
	name := ""
	typ := "text"
	for _, attr := range n.Attr {
		if attr.Key == "name" {
			name = attr.Val
		}
		if attr.Key == "type" {
			typ = attr.Val
		}
	}
	if name != "" {
		results = append(results, InjectionPoint{
			URL:         baseURL,
			ParamName:   name,
			InputType:   typ,
			Context:     "form-input",
			Description: fmt.Sprintf("Form input found: %s", name),
		})
	}
}

func handleImage(baseURL string, n *html.Node) {
	for _, attr := range n.Attr {
		if attr.Key == "onerror" {
			addInjectionPoint(baseURL, "IMG", "img-onerror", true, "Image with inline onerror attribute", nil)
		}
	}
}

func handleMeta(baseURL string, n *html.Node) {
	for _, attr := range n.Attr {
		if attr.Key == "http-equiv" && strings.Contains(strings.ToLower(attr.Val), "refresh") {
			addInjectionPoint(baseURL, "META", "meta-refresh", true, "Meta refresh tag present", nil)
		}
	}
}

func handleScript(baseURL string, n *html.Node) {
	src := ""
	for _, attr := range n.Attr {
		if attr.Key == "src" {
			src = resolveURL(baseURL, attr.Val)
		}
	}
	if src != "" {
		host := getHost(src)
		resp, err := clients[host].Client.Get(src)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		analyzeJS(string(body), src)
	} else if n.FirstChild != nil {
		analyzeJS(n.FirstChild.Data, baseURL)
	}
}

func analyzeJS(js, location string) {
	for _, re := range patterns {
		if re.MatchString(js) {
			addInjectionPoint(location, "JS", "script", true, fmt.Sprintf("Pattern match: %s", re.String()), nil)
		}
	}
}

func resolveURL(baseURL, href string) string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return href
	}
	ref, err := url.Parse(href)
	if err != nil {
		return href
	}
	return base.ResolveReference(ref).String()
}

func getHost(link string) string {
	u, err := url.Parse(link)
	if err != nil {
		return baseDomain
	}
	return u.Host
}

func addInjectionPoint(url, method, context string, suspicious bool, desc string, headers http.Header) {
	results = append(results, InjectionPoint{
		URL:         url,
		Method:      method,
		Context:     context,
		Suspicious:  suspicious,
		Description: desc,
		Headers:     headers,
	})
}
