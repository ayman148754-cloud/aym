cat << 'EOF' > gofuzz.go
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ألوان للترمنال
const (
	Info  = "\033[34m[INFO]\033[0m"
	Found = "\033[32m[FOUND]\033[0m"
	Warn  = "\033[33m[WARN]\033[0m"
	Reset = "\033[0m"
)

func worker(url string, jobs <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	client := &http.Client{Timeout: 5 * time.Second}

	for path := range jobs {
		fullURL := strings.TrimSuffix(url, "/") + "/" + strings.TrimPrefix(path, "/")
		req, _ := http.NewRequest("GET", fullURL, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Security-Researcher)")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			fmt.Printf("%s %-30s %s(Status: 200)%s\n", Found, fullURL, "\033[32m", Reset)
		} else if resp.StatusCode == 403 {
			fmt.Printf("%s %-30s %s(Status: 403)%s\n", Warn, fullURL, "\033[33m", Reset)
		}
		resp.Body.Close()
	}
}

func main() {
	target := flag.String("u", "", "Target URL (e.g., https://google.com)")
	wordlist := flag.String("w", "", "Path to wordlist file")
	threads := flag.Int("t", 20, "Number of concurrent threads")
	flag.Parse()

	if *target == "" || *wordlist == "" {
		fmt.Println("Usage: go run gofuzz.go -u <url> -w <wordlist> [-t threads]")
		return
	}

	file, err := os.Open(*wordlist)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer file.Close()

	fmt.Printf("%s Starting scan on: %s with %d threads\n", Info, *target, *threads)

	jobs := make(chan string)
	var wg sync.WaitGroup

	// تشغيل العمال (Workers) حسب عدد الـ Threads
	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go worker(*target, jobs, &wg)
	}

	// إرسال الكلمات للعمال
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		jobs <- scanner.Text()
	}
	close(jobs)

	wg.Wait()
	fmt.Printf("%s Scan Completed.\n", Info)
}
EOF
