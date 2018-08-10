package main

import (
	"errors"
	"flag"
	"golang.org/x/crypto/acme/autocert"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

var (
	configFilename = flag.String("config", "config.yaml", "The filename of the configuration")
)

const (
	certPattern     = "/cert/"
	RenewalfileName = "renewal.yaml"
)

type baseConfig struct {
	HttpAddress       string        `yaml:"http_address"`
	CertStoreName     string        `yaml:"Certdirectory"`
	CertRenewAfterMin time.Duration `yaml:"CertRenewAfterMin"`
}
type RuntimeState struct {
	Config           baseConfig
	CacheStore       autocert.DirCache
	CertMutex        sync.Mutex
	Renewalinfo      map[string]RenewalInfo
	RenewalInfoMutex sync.Mutex
}

type RenewalInfo struct {
	CertGeneratedTime  int64 `yaml:"CertGeneratedTime"`
	RenewCertAfterTime int64 `yaml:"RenewCertAfterTime"`
}

//parses the config file
func parseConfig(configFilename string) (RuntimeState, error) {

	var state RuntimeState

	if _, err := os.Stat(configFilename); os.IsNotExist(err) {
		err = errors.New("mising config file failure")
		return state, err
	}

	//ioutil.ReadFile returns a byte slice (i.e)(source)
	source, err := ioutil.ReadFile(configFilename)
	if err != nil {
		err = errors.New("cannot read config file")
		return state, err
	}

	//Unmarshall(source []byte,out interface{})decodes the source byte slice/value and puts them in out.
	err = yaml.Unmarshal(source, &state.Config)

	if err != nil {
		err = errors.New("Cannot parse config file")
		log.Printf("Source=%s", source)
		return state, err
	}
	state.CacheStore = autocert.DirCache(state.Config.CertStoreName)
	state.Renewalinfo = make(map[string]RenewalInfo)
	return state, err
}

//The Commented section in Main func is logic for getting certificate and automatic renewal after it expires(after renew timer(in autocert.Manager) count down is complemented)
func main() {
	flag.Parse()

	state, err := parseConfig(*configFilename)

	if err != nil {
		log.Println("Error while parsing Config file", err)
		return
	}
	//mux:=http.NewServeMux()
	http.Handle(certPattern, http.HandlerFunc(state.DomainCertHandler))
	http.Handle("/", http.HandlerFunc(state.IndexHandler))

	/*
		m := &autocert.Manager{
			Cache:      state.CacheStore,
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist("cert-manager.com"),
		}

		s := &http.Server{
			Addr:      ":mux",
			Handler:mux,
			TLSConfig: m.TLSConfig(),
		}
		go http.ListenAndServe("",m.HTTPHandler(nil))

		s.ListenAndServeTLS("", "")
	*/
	state.GetRenewalInfo()
	go state.CheckRenewalStatus()
	log.Fatal(http.ListenAndServe(state.Config.HttpAddress, nil))
}
