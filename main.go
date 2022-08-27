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
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

//go:embed index.html
var f embed.FS

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

func fileHandler(w http.ResponseWriter, r *http.Request) {
	log.Println(r.RemoteAddr + " - " + r.Method + " " + r.URL.RequestURI() + " - " + r.UserAgent())
	log.Println("Subject: " + r.TLS.PeerCertificates[0].Subject.String() + " - " +
		r.TLS.PeerCertificates[0].SerialNumber.String())
	w.Header().Set("Server", "MTLS File Server ")

	var index Index
	index.Title = r.URL.RequestURI()

	switch r.Method {
	case "GET":
		p := "./" + r.TLS.PeerCertificates[0].Subject.Organization[0] + r.URL.Path
		log.Println("Local path: " + p)
		if strings.HasSuffix(p, "/") {
			var err error
			files, err := ioutil.ReadDir(p)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprintln(w, "404 page not found")
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
}

func main() {

	var caFile, certFile, keyFile, listen string

	flag.StringVar(&caFile, "cafile", "", "")
	flag.StringVar(&certFile, "certfile", "", "")
	flag.StringVar(&keyFile, "keyfile", "", "")
	flag.StringVar(&listen, "listen", ":8443", "")
	flag.Parse()

	if len(os.Args) == 1 {
		help()
		os.Exit(1)
	}

	logger := log.New(os.Stdout, "http: ", log.LstdFlags)
	logger.Println("Server is starting...")
	logger.Println("CA File  : " + caFile)
	logger.Println("Cert File: " + certFile)
	logger.Println("Key file : " + keyFile)
	logger.Println("Listen   : " + listen)
	http.HandleFunc("/", fileHandler)

	// Create a CA certificate pool and add cert.pem to it
	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create the TLS Config with the CA pool and enable Client certificate validation
	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	tlsConfig.BuildNameToCertificate()

	// Create a Server instance to listen on port 8443 with the TLS config
	server := &http.Server{
		Addr:      listen,
		TLSConfig: tlsConfig,
	}

	// Listen to HTTPS connections with the server certificate and wait
	log.Fatal(server.ListenAndServeTLS(certFile, keyFile))
}
