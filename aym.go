package main

import (
 "bufio"
 "crypto/tls"
 "flag"
 "fmt"
 "net/http"
 "os"
 "strings"
 "sync"
 "time"
)

// تعريف الألوان الاحترافية
const (
 Reset      = "\033[0m"
 Red        = "\033[31m"
 Green      = "\033[32m"
 Yellow     = "\033[33m"
 Blue       = "\033[34m"
 Purple     = "\033[35m"
 Cyan       = "\033[36m"
 Gray       = "\033[37m"
 BoldRed    = "\033[1;31m"
 BoldYellow = "\033[1;33m"
)

// شعار الأداة (Banner)
func printBanner() {
 banner := `
    _       __ 
   /   |\ \ / /|  \/  |
  / /| | \   / | \  / |
 / ___ |  | |  | |\/| |
/_/  |_|  |_|  |_|  |_| v3.0 [Enhanced Security]
    `
 fmt.Printf("%s%s%s\n", Purple, banner, Reset)
 fmt.Printf("%s > Advanced Path Fuzzer & Security Severity Scanner%s\n", Gray, Reset)
 fmt.Printf("%s > Created by: ayman147754@gmail.com%s\n\n", Blue, Reset)
}

func main() {
 // تعريف الـ Flags
 target := flag.String("u", "", "Target URL (e.g., https://example.com)")
 wordlist := flag.String("w", "", "Path to wordlist file")
 threads := flag.Int("t", 50, "Number of concurrent threads")
 output := flag.String("o", "", "File to save the output results")
 timeout := flag.Int("timeout", 5, "Request timeout in seconds")
 
 flag.Parse()

 printBanner()

 if *target == "" || *wordlist == "" {
  fmt.Printf("%s[!] Usage: aym -u <url> -w <wordlist> [-o output.txt] [-t 100]%s\n", Red, Reset)
  return
 }

 // فتح ملف المسارات
 file, err := os.Open(*wordlist)
 if err != nil {
  fmt.Printf("%s[!] Error opening wordlist: %v%s\n", Red, err, Reset)
  return
 }
 defer file.Close()

 // ملف حفظ النتائج
 var outFile *os.File
 if *output != "" {
  outFile, _ = os.Create(*output)
  defer outFile.Close()
 }

 // إعداد العميل (Client)
 client := &http.Client{
  Transport: &http.Transport{
   TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
  },
  Timeout: time.Duration(*timeout) * time.Second,
 }

 fmt.Printf("%s[%s]%s Starting Security Scan... Target: %s\n", Purple, time.Now().Format("15:04:05"), Reset, *target)
 fmt.Println("----------------------------------------------------------------------")

 jobs := make(chan string, *threads)
 var wg sync.WaitGroup

 // تشغيل العمال (Workers)
 for i := 0; i < *threads; i++ {
  wg.Add(1)
  go func() {
   defer wg.Done()
   for path := range jobs {
    fullURL := strings.TrimSuffix(*target, "/") + "/" + strings.TrimPrefix(path, "/")
    
    req, _ := http.NewRequest("GET", fullURL, nil)
    req.Header.Set("User-Agent", "AYM-Security-Scanner/3.0")

    resp, err := client.Do(req)
    if err != nil {
     continue
    }

    status := resp.StatusCode
    if status != 404 {
     severity := "[INFO]"
     color := Green
     lowerPath := strings.ToLower(path)

     // --- نظام تصنيف الخطورة ---
     
     // 1. خطورة قصوى (Critical) - ملفات حساسة
     if strings.Contains(lowerPath, ".env")  strings.Contains(lowerPath, "config")  
        strings.Contains(lowerPath, ".git")  strings.Contains(lowerPath, "backup")  
        strings.Contains(lowerPath, "sql") || strings.Contains(lowerPath, "db") {
      severity = "[CRITICAL]"
      color = BoldRed
      fmt.Print("\a") // صوت تنبيه (Beep) للثغرات الخطيرة
     } else if strings.Contains(lowerPath, "admin")  strings.Contains(lowerPath, "login")  
               strings.Contains(lowerPath, "panel")  status == 403  status == 401 {
      // 2. خطورة عالية (High) - لوحات تحكم
      severity = "[HIGH]"
      color = BoldYellow
     }

     result := fmt.Sprintf("%-10s [%d] %s (Size: %d)", severity, status, fullURL, resp.ContentLength)
     fmt.Printf("%s%s%s\n", color, result, Reset)

     if outFile != nil {
      outFile.WriteString(result + "\n")
     }
    }
    resp.Body.Close()
   }
  }()
 }

 // إرسال الكلمات من ملف المسارات
 scanner := bufio.NewScanner(file)
 for scanner.Scan() {
  jobs <- scanner.Text()
 }
 close(jobs)
 wg.Wait()

 fmt.Printf("\n%s[+] Security scan finished at %s. Results saved to: %s%s\n", Green, time.Now().Format("15:04:05"), *output, Reset)
}
