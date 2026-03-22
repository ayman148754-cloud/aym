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

// الألوان
const (
 Reset  = "\033[0m"
 Red    = "\033[31m"
 Green  = "\033[32m"
 Yellow = "\033[33m"
 Blue   = "\033[34m"
 Purple = "\033[35m"
 Cyan   = "\033[36m"
 Gray   = "\033[37m"
)

// شعار الأداة (Banner) مثل نيوكلي
func printBanner() {
 banner := `
    _       __ 
   /   |\ \ / /|  \/  |
  / /| | \   / | \  / |
 / ___ |  | |  | |\/| |
/_/  |_|  |_|  |_|  |_| v2.0
    `
 fmt.Printf("%s%s%s\n", Purple, banner, Reset)
 fmt.Printf("%s > Advanced Path Fuzzer & Security Scanner%s\n", Gray, Reset)
 fmt.Printf("%s > Created by: ayman147754@gmail.com%s\n\n", Blue, Reset)
}

func main() {
 // تعريف الـ Flags مثل الأدوات القوية
 target := flag.String("u", "", "Target URL to scan")
 wordlist := flag.String("w", "", "Path to wordlist file")
 threads := flag.Int("t", 50, "Number of concurrent threads (default 50)")
 output := flag.String("o", "", "File to save the output results")
 timeout := flag.Int("timeout", 5, "Request timeout in seconds")
 
 flag.Parse()

 printBanner()

 // التحقق من المدخلات الأساسية
 if *target == "" || *wordlist == "" {
  fmt.Printf("%s[!] Usage: aym -u <url> -w <wordlist> -o <output>%s\n", Red, Reset)
  flag.PrintDefaults()
  return
 }

 // فتح ملف المسارات
 file, err := os.Open(*wordlist)
 if err != nil {
  fmt.Printf("%s[!] Error opening wordlist: %v%s\n", Red, err, Reset)
  return
 }
 defer file.Close()

 // إعداد حفظ النتائج في ملف إذا طلب المستخدم (-o)
 var outFile *os.File
 if *output != "" {
  outFile, _ = os.Create(*output)
  defer outFile.Close()
 }

 // إعدادات الاتصال (Skip SSL)
 client := &http.Client{
  Transport: &http.Transport{
   TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
  },
  Timeout: time.Duration(*timeout) * time.Second,
 }

 fmt.Printf("%s[%s]%s Starting scan on: %s\n", Purple, time.Now().Format("15:04:05"), Reset, *target)
 fmt.Println("--------------------------------------------------")

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
    req.Header.Set("User-Agent", "AYM-Scanner/2.0")

    resp, err := client.Do(req)
    if err != nil {
     continue
    }

    status := resp.StatusCode
    // طباعة النتائج المهمة فقط
    if status != 404 {
     result := fmt.Sprintf("[%d] %s (Size: %d)", status, fullURL, resp.ContentLength)
     
     // تلوين المخرجات حسب الكود
     color := Cyan
     if status == 200 { color = Green }
     if status == 403 || status == 401 { color = Yellow }

     fmt.Printf("%s%s%s\n", color, result, Reset)

     // حفظ في الملف إذا كان الـ flag -o موجوداً
     if outFile != nil {
      outFile.WriteString(result + "\n")
     }
    }
    resp.Body.Close()
   }
  }()
 }

 // إرسال البيانات
 scanner := bufio.NewScanner(file)
 for scanner.Scan() {
  jobs <- scanner.Text()
 }
 close(jobs)
 wg.Wait()

 fmt.Printf("\n%s[+] Scan finished at %s%s\n", Green, time.Now().Format("15:04:05"), Reset)
}
