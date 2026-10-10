package handler


import (
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/PuerkitoBio/goquery"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	// https://blog.banyunxiaoxi.icu/
	q, _ := http.NewRequest("GET", "https://blog.banyunxiaoxi.icu/", nil)
	q.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	res, err := client.Do(q)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Request Home Fail:" + err.Error()))
		return
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Request Home Status Fail:" + err.Error()))
		return
	}
	a, _ := io.ReadAll(res.Body)
	w.Write(a)
	return
	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return
	}
	thumb := doc.Find("div.article-panel").First().Find(".a-thumb a")
	href, exist := thumb.Attr("href")
	if !exist {
		return
	}

	page, _ := http.NewRequest("GET", href, nil)
	page.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
	pageRes, err := client.Do(page)
	if err != nil {
		return
	}
	defer pageRes.Body.Close()
	if pageRes.StatusCode != 200 {
		return
	}
	pageDoc, err := goquery.NewDocumentFromReader(pageRes.Body)
	if err != nil {
		return
	}
	pre := pageDoc.Find("code")
	pre.Find(".__cf_email__").Each(func(i int, s *goquery.Selection) {
		//解密邮箱cloudflare
		email, exist := s.Attr("data-cfemail")
		if exist {
			e := ""
			p, pErr := hex.DecodeString(email)
			if pErr != nil {
				return
			}
			r := p[0]
			for n := 0; len(p)-1 > n; n++ {
				e += string(p[n+1] ^ r)
			}
			s.SetText(e)
		}
	})
	ips := pre.Text()

	w.Header().Set("Content-Type", "application/json")
	if ips == "" {
		w.Write([]byte("Not Sub Node"))
		return
	}
	w.Write([]byte("star\r\n"))
	s := base64.StdEncoding.EncodeToString([]byte(ips))
	w.Write([]byte(s))
}

