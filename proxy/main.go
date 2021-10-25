package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

var (
	username, password string
	access             []allowedIP
)

type allowedIP struct {
	IP         string
	LastAccess string
	Auth       string
}

// Source for proxy
// https://blog.joshsoftware.com/2021/05/25/simple-and-powerful-reverseproxy-in-go/

func main() {

	forward := flag.String("forward", "localhost", "address proxy should forward to")
	flag.StringVar(&username, "username", "test", "username to login with")
	flag.StringVar(&password, "password", "password", "password to login with")

	flag.Parse()

	log.Printf("Starting proxy to reverse to address[%s]", *forward)
	url, err := url.Parse(*forward)
	if err != nil {
		log.Fatalf("The address[%s] could not be parsed", *forward)
	}

	proxy := httputil.NewSingleHostReverseProxy(url)

	http.HandleFunc("/unlock", basicAuth)
	http.HandleFunc("/", ProxyRequestHandler(proxy))
	log.Fatal(http.ListenAndServe(":8080", nil))

}

// ProxyRequestHandler handles the http request using proxy
func ProxyRequestHandler(proxy *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if !hasAccess(r.Header.Get("X-FORWARDED-FOR")) {
			w.WriteHeader(http.StatusNotAcceptable)
			return
		}
		proxy.ServeHTTP(w, r)
	}
}

func basicAuth(w http.ResponseWriter, r *http.Request) {
	user, pass, _ := r.BasicAuth()
	log.Printf("user:%s pass: %s. expected user:%s pass: %s", user, pass, username, password)
	if user != username || pass != password {
		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(w, "Unauthorized.", http.StatusUnauthorized)
		return
	}

	IP := r.Header.Get("X-FORWARDED-FOR")
	log.Printf("IP[%s] has accessed list", IP)

	addAccess(IP)

	authed, err := json.MarshalIndent(access, "", "    ")
	if err != nil {
		log.Printf("error displaying auth list %+v", err)
		http.Error(w, "failed to display auth list", http.StatusInternalServerError)
	}
	w.Write(authed)
}

func addAccess(IP string) {
	if !hasAccess(IP) {
		access = append(access, allowedIP{IP: IP, Auth: time.Now().String()})
	}
}

func hasAccess(IP string) bool {
	for _, a := range access {
		if a.IP == IP {
			return true
		}
	}
	return false
}
