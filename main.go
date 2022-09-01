/*
Idnaf MTLS File Server is a file server that host files from Organization perspective
You need a certitificate within organization to access the organization directory.
e.g.
Certificate with subject DN CN=client,OU=Dev,O=Idnaf,ST=DKI Jakarta,C=ID will have access to ./Idnaf directory on the executable directory
*/
package main

import (
	"crypto/tls"
	"crypto/x509"
	"embed"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

//go:embed index.html
var f embed.FS

//go:embed banner.txt
var banner string

type File struct {
	Name  string
	URI   string
	IsDir bool
	Size  int64
}
type Index struct {
	Title    string
	LoggedIn string
	Files    []File
}

var admin string

func uploadFile(w http.ResponseWriter, r *http.Request) {
	p := "." + r.URL.Path
	err := os.MkdirAll(filepath.Dir(p), 0644)
	file, err := os.Create(p)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	size, err := io.Copy(file, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	file.Close()
	log.Printf("Successfully write to file: %s size=%d", p, size)
}

func fileHandler(w http.ResponseWriter, r *http.Request) {
	log.Println(r.RemoteAddr + " - " + r.Method + " " + r.URL.RequestURI() + " - " + r.UserAgent())
	log.Println("Subject: " + r.TLS.PeerCertificates[0].Subject.String() + " - " +
		r.TLS.PeerCertificates[0].SerialNumber.String())
	w.Header().Set("Server", "MTLS File Server ")

	var index Index
	index.Title = r.URL.RequestURI()

	switch r.Method {
	case "DELETE":
		if r.TLS.PeerCertificates[0].Subject.Organization[0] != admin {
			log.Println("Invalid privilege")
			http.Error(w, "Invalid privilege", http.StatusForbidden)
			return
		}
		err := os.Remove("." + r.URL.Path)
		if err != nil {
			log.Println(err.Error())
			http.Error(w, "Could not delete file", http.StatusNotFound)
			return
		}
		log.Printf("Successfully delete file %s", r.URL.Path)
		break
	case "POST":
		if r.TLS.PeerCertificates[0].Subject.Organization[0] != admin {
			log.Println("Invalid privilege")
			http.Error(w, "Invalid privilege", http.StatusForbidden)
			return
		}
		uploadFile(w, r)
		break
	case "GET":
		p := "./" + r.TLS.PeerCertificates[0].Subject.Organization[0] + r.URL.Path
		log.Println("Local path: " + p)
		if strings.HasSuffix(p, "/") {
			var err error
			files, err := ioutil.ReadDir(p)
			if err != nil {
				log.Println(err)
				http.Error(w, "404 page not found", http.StatusNotFound)
				return
			}
			index.LoggedIn = r.TLS.PeerCertificates[0].Subject.String()
			for _, file := range files {
				if file.IsDir() {
					index.Files = append(index.Files, File{IsDir: true, URI: r.URL.Path + file.Name(), Name: file.Name(), Size: 0})
				}
			}
			for _, file := range files {
				if !file.IsDir() {
					index.Files = append(index.Files, File{IsDir: false, URI: r.URL.Path + file.Name(), Name: file.Name(), Size: file.Size()})
				}
			}
			var tmpl *template.Template
			tmpl, err = template.ParseFS(f, "index.html")
			if err != nil {
				log.Println(err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			err = tmpl.Execute(w, index)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		} else {
			http.ServeFile(w, r, p)
		}
		break
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintln(w, "405 method not allowed")
		return
	}
}

func help() {
	fmt.Println("Idnaf Mutual Authenticate file server")
	fmt.Println("Usage:")
	fmt.Println(" -cafile   : CA file in PEM format (Mandatory)")
	fmt.Println(" -certfile : Cert file in PEM format (Mandatory)")
	fmt.Println(" -keyfile  : Private key file in PEM format (Mandatory)")
	fmt.Println(" -listen   : Listen port default :8443 (Optional)")
	fmt.Println(" -admin    : Admin organization name default Admin (Optional)")
}

func main() {

	var caFile, certFile, keyFile, listen string

	flag.StringVar(&caFile, "cafile", "", "")
	flag.StringVar(&certFile, "certfile", "", "")
	flag.StringVar(&keyFile, "keyfile", "", "")
	flag.StringVar(&listen, "listen", ":8443", "")
	flag.StringVar(&admin, "admin", "Admin", "")
	flag.Parse()

	if len(os.Args) == 1 {
		help()
		os.Exit(1)
	}

	fmt.Println(banner)
	log.Println("Server is starting...")
	log.Println("CA File  : " + caFile)
	log.Println("Cert File: " + certFile)
	log.Println("Key file : " + keyFile)
	log.Println("Listen   : " + listen)
	log.Println("Admin    : " + admin)
	http.HandleFunc("/", fileHandler)

	// Create a CA certificate pool and add cert.pem to it
	caCert, err := ioutil.ReadFile(filepath.Clean(caFile))
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create the TLS Config with the CA pool and enable Client certificate validation
	tlsConfig := &tls.Config{
		ClientCAs:                caCertPool,
		ClientAuth:               tls.RequireAndVerifyClientCert,
		MinVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
	}
	tlsConfig.BuildNameToCertificate()

	// Create a Server instance to listen on port 8443 with the TLS config
	server := &http.Server{
		Addr:              listen,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 2 * time.Second,
	}

	// Listen to HTTPS connections with the server certificate and wait
	log.Fatal(server.ListenAndServeTLS(certFile, keyFile))
}
