package main

import (
"bufio"
"crypto/tls"
"flag"
"fmt"
"io/ioutil"
"net"
"net/http"
"os"
"strings"
"sync"
"time"
)

// نظام الألوان الكريستالي المتطور
const (
Reset       = "\033[0m"
RedCrystal  = "\033[1;91m" 
Gold        = "\033[1;33m" 
Emerald     = "\033[1;32m" 
SkyBlue     = "\033[1;34m" 
NeonPurple  = "\033[1;35m" 
White       = "\033[1;37m"
Gray        = "\033[2;37m"
)

func printBanner() {
banner := `
    █████╗ ██╗   ██╗███╗   ███╗    ██╗   ██╗███████╗
    ██╔══██╗╚██╗ ██╔╝████╗ ████║    ██║   ██║██╔════╝
    ███████║ ╚████╔╝ ██╔████╔██║    ██║   ██║███████╗
    ██╔══██║  ╚██╔╝  ██║╚██╔╝██║    ╚██╗ ██╔╝╚════██║
    ██║  ██║   ██║   ██║ ╚═╝ ██║     ╚████╔╝ ███████║
    ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝      ╚═══╝  ╚══════╝
    >> LEGENDARY SECURITY SCANNER v5.0 <<
    `
fmt.Printf("%s%s%s\n", NeonPurple, banner, Reset)
fmt.Printf("%s > Powered by Ayman Intelligence Engine%s\n", Gold, Reset)
fmt.Printf("%s > Full Recon, Subdomains, Fuzzing & Leak Detection%s\n\n", White, Reset)
}

func main() {
target := flag.String("u", "", "Target URL/Domain")
wordlist := flag.String("w", "", "Main Wordlist")
threads := flag.Int("t", 150, "Threads (Speed)")
show404 := flag.Bool("all", false, "Show 404 results in Blue")
flag.Parse()

if *target == "" || *wordlist == "" {
  printBanner()
  fmt.Printf("%s[!] Usage: aym -u target.com -w list.txt [-t 200] [-all]%s\n", RedCrystal, Reset)
  return
}

printBanner()
startTime := time.Now()

client := &http.Client{
  Transport: &http.Transport{
   TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
   DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
  },
  Timeout: 10 * time.Second,
}

fmt.Printf("%s[*] INFO: Scanning Started at %s%s\n", Gray, startTime.Format("15:04:05"), Reset)
fmt.Println(strings.Repeat("-", 70))

// المرحلة 1: جمع المعلومات الاستخباراتية
go scanSubdomains(*target, *wordlist, *threads)

// المرحلة 2: الفحص العميق
scanPaths(client, *target, *wordlist, *threads, *show404)

fmt.Println(strings.Repeat("-", 70))
fmt.Printf("%s[+] FINISHED: Total Time: %v%s\n", Emerald, time.Since(startTime), Reset)
}

func scanSubdomains(target, wordlist string, threads int) {
file, _ := os.Open(wordlist)
defer file.Close()
scanner := bufio.NewScanner(file)
var wg sync.WaitGroup
jobs := make(chan string, threads)

for i := 0; i < threads; i++ {
  wg.Add(1)
  go func() {
   defer wg.Done()
   for sub := range jobs {
    host := sub + "." + strings.TrimPrefix(target, "https://")
    if _, err := net.LookupHost(host); err == nil {
     fmt.Printf("%s[DNS-FOUND] %-30s %s\n", Emerald, host, Reset)
    }
   }
  }()
}
for scanner.Scan() { jobs <- scanner.Text() }
close(jobs)
wg.Wait()
}

func scanPaths(client *http.Client, target string, wordlist string, threads int, show404 bool) {
file, _ := os.Open(wordlist)
defer file.Close()
scanner := bufio.NewScanner(file)
var wg sync.WaitGroup
jobs := make(chan string, threads)

for i := 0; i < threads; i++ {
  wg.Add(1)
  go func() {
   defer wg.Done()
   for path := range jobs {
    fullURL := fmt.Sprintf("https://%s/%s", strings.TrimPrefix(target, "https://"), path)
    
    req, _ := http.NewRequest("GET", fullURL, nil)
    // تضليل الـ WAF
    req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AYM-Legendary/5.0")
    req.Header.Set("X-Forwarded-For", "127.0.0.1")

    resp, err := client.Do(req)
    if err != nil { continue }
    
    body, _ := ioutil.ReadAll(resp.Body)
    resp.Body.Close()

    status := resp.StatusCode
    size := len(body)
    lowerPath := strings.ToLower(path)

    // نظام التصنيف الأسطوري
    if status == 404 {
     if show404 {
      fmt.Printf("%s[404] %-50s %s\n", SkyBlue, fullURL, Reset)
     }
    } else {
     severity := "[LOW]"
     color := Emerald

     // كشف الثغرات القاتلة (Critical)
     if strings.Contains(lowerPath, ".env")  strings.Contains(lowerPath, "config")  
        strings.Contains(lowerPath, "sql")  strings.Contains(lowerPath, ".git")  
        strings.Contains(string(body), "DB_PASSWORD") || strings. Contains(string(body), "AWS_SECRET") {
      severity = "[CRITICAL]"
      color = RedCrystal
      fmt.Print("\a\a") // تنبيه مكرر
     } else if status == 403  strings.Contains(lowerPath, "admin")  status == 401 {
      severity = "[HIGH]"
      color = Gold
     }

     fmt.Printf("%s%-10s [%d] %-45s (Size: %d)%s\n", color, severity, status, fullURL, size, Reset)
    }
   }
  }()
}
for scanner.Scan() { jobs <- scanner.Text() }
close(jobs)
wg.Wait()
}
