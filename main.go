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
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

func fileHandler(w http.ResponseWriter, r *http.Request) {
	log.Println(r.RemoteAddr + " - " + r.Method + " " + r.URL.RequestURI() + " - " + r.UserAgent())
	log.Println("Subject: " + r.TLS.PeerCertificates[0].Subject.String() + " - " +
		r.TLS.PeerCertificates[0].SerialNumber.String())
	w.Header().Set("Server", "MTLS File Server ")
	switch r.Method {
	case "GET":
		p := "./" + r.TLS.PeerCertificates[0].Subject.Organization[0] + r.URL.Path
		log.Println("Local path: " + p)
		if strings.HasSuffix(p, "/") {
			files, err := ioutil.ReadDir(p)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprintln(w, "404 page not found")
				return
			}
			fmt.Fprintln(w, `
			<!DOCTYPE html>
			<html>
			<head>
			<style>
				* {
					font-family: Arial, Helvetica, sans-serif;
				}
				table {
				  border-collapse: collapse;
				  width: 100%;
				}
				th, td {
				  padding: 8px;
				  text-align: left;
				  border-bottom: 1px solid #DDD;
				}				
				tr:hover {background-color: #D6EEEE;}
				</style>
			</head>
			<body>
			<b>Secured access</b><br>Login as `, r.TLS.PeerCertificates[0].Subject.String(), `<br>
			<table><tr><th>Name</th><th>Size</th></tr>`)
			for _, file := range files {
				if file.IsDir() {
					fmt.Fprintln(w, "<tr><td><b><a href="+r.URL.Path+file.Name()+">"+file.Name()+"</a></b></td><td>Directory</td></tr>")
				}
			}
			for _, file := range files {
				if !file.IsDir() {
					fmt.Fprintln(w, "<tr><td><a href="+r.URL.Path+file.Name()+">"+file.Name()+"</a></td><td>"+strconv.FormatInt(file.Size(), 10)+"</td></tr>")
				}
			}
			fmt.Fprintf(w, "</table></body></html>")
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
