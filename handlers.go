package main

import (
	"context"
	"fmt"
	"golang.org/x/crypto/acme/autocert"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

/*
Cache Schema:

Cache is implemented as directory. All certificates will be in "certs" directory. When a request for certificate for new domain comes up. After getting the certificate, it creates a
new directory with domainname as directory name and stores the certificate there. We will also store private key


TODO: filename safe (filename validiation), (domain name validation)
*/

//This function has generate certificate which gets from acme server and then put into cache store. also create renewal.yaml file which consists of certificate creation and expiration details
func (state *RuntimeState) GenerateCert(domain string) ([]byte, error) {

	//generate new cert logic comes here and put in cache store
	//sleep for 10 secs to emulate external service call
	time.Sleep(time.Second * 10)
	newcert := "foo-$" + domain

	ctx := context.Background()

	state.CertMutex.Lock()

	defer state.CertMutex.Unlock()

	domainDir := filepath.Join(state.Config.CertStoreName, domain)

	certstoreDir := autocert.DirCache(domainDir)
	//for every new domain name we create a new directory in "certs"(Cachestore) and store the cert.

	err := certstoreDir.Put(ctx, domain, []byte(newcert))
	if err != nil {
		log.Println(err)
		return nil, err
	}
	renewinfo := RenewalInfo{time.Now().Unix(), time.Now().Add(time.Minute * state.Config.CertRenewAfterMin).Unix()}
	out, err := yaml.Marshal(renewinfo)
	if err != nil {
		log.Println(err)
	}
	err = certstoreDir.Put(ctx, RenewalfileName, out)
	if err != nil {
		log.Println(err)
	}
	state.RenewalInfoMutex.Lock()
	state.Renewalinfo[domain] = renewinfo
	state.RenewalInfoMutex.Unlock()
	return []byte(newcert), nil
}

//domain cert handler gets requests and parses the url path to get the domain name information, It doesn't have input(domain name) validation at the moment but can add based on validation requirements
func (state *RuntimeState) DomainCertHandler(w http.ResponseWriter, r *http.Request) {

	fixedUrl := certPattern

	fixedUrlLength := len(fixedUrl)

	urlPath := r.URL.Path
	urlPathLength := len(urlPath)

	//extract domain name from url
	domainName := urlPath[fixedUrlLength:urlPathLength]

	domainCert, err := state.GetCertificatefromCache(domainName)
	if err != nil {
		if err == autocert.ErrCacheMiss {
			domainCert, err := state.GenerateCert(domainName)
			if err != nil {
				log.Println("error while getting cert", err)
				http.Error(w, fmt.Sprint("Error while Getting Certificate from cache store", err), http.StatusInternalServerError)
				return
			}
			fmt.Fprintf(w, string(domainCert))
			return
		} else {
			log.Println("error while getting cert", err)
			http.Error(w, fmt.Sprint("Error while Getting Certificate from cache store", err), http.StatusInternalServerError)
			return
		}
	}
	fmt.Fprintf(w, string(domainCert))
}

//Get certificate from cache store
func (state *RuntimeState) GetCertificatefromCache(domainName string) ([]byte, error) {
	ctx := context.Background()

	CertDir := filepath.Join(state.Config.CertStoreName, domainName)

	certStoreDir := autocert.DirCache(CertDir)
	state.CertMutex.Lock()
	defer state.CertMutex.Unlock()
	certificate, err := certStoreDir.Get(ctx, domainName)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return certificate, nil
}

//Get Certificate expiration/renewal info into state.
//If program restarts it would have the state information, so 1st get expiration information from cache and store it in state.
func (state *RuntimeState) GetRenewalInfo() {
	dir, err := os.Open(state.Config.CertStoreName)
	if err != nil {
		return
	}
	defer dir.Close()
	getAllDir, err := dir.Readdirnames(-1)
	if err != nil {
		return
	}
	for _, eachDir := range getAllDir {
		go state.GetCertExpirationtime(eachDir)
	}

}

//Gets expiration time and puts it into renewal info map
func (state *RuntimeState) GetCertExpirationtime(eachDir string) {
	fileNewPath := filepath.Join(state.Config.CertStoreName, eachDir, RenewalfileName)
	yamlFile, err := ioutil.ReadFile(fileNewPath)
	if err != nil {
		log.Printf("yamlFile ", err)
		return
	}
	renew := RenewalInfo{}
	err = yaml.Unmarshal(yamlFile, &renew)
	if err != nil {
		log.Println("Unmarshal: %v", err)
		return
	}
	state.RenewalInfoMutex.Lock()
	state.Renewalinfo[eachDir] = renew
	state.RenewalInfoMutex.Unlock()
}

//checks if the certs need to be renewed or not.
func (state *RuntimeState) CheckRenewalStatus() {
	for {
		//To avoid concurrent map iteration and map write
		renewalinfoMap := state.Renewalinfo
		for key, value := range renewalinfoMap {
			if time.Now().Unix() > value.RenewCertAfterTime {
				fmt.Println("Hey I'm renewing")
				state.RenewCertsforDomain(key)
			}
		}
		time.Sleep(time.Minute * 1)
	}
}

//Renew expired certs.
func (state *RuntimeState) RenewCertsforDomain(domain string) {
	//1st generate new cert
	//sleep for 10 secs to emulate external service call
	time.Sleep(time.Second * 10)

	newcert := "foo-$" + domain
	//once cert is succesfull delete the current files
	ctx := context.Background()
	state.CertMutex.Lock()
	defer state.CertMutex.Unlock()
	currentCertDir := autocert.DirCache(filepath.Join(state.Config.CertStoreName, domain))
	//delete the cert file
	currentCertDir.Delete(ctx, domain)
	//delete renewal.yaml file
	currentCertDir.Delete(ctx, RenewalfileName)

	//next put new cert into that directory
	err := currentCertDir.Put(ctx, domain, []byte(newcert))
	if err != nil {
		log.Println(err)
	}
	renewinfo := RenewalInfo{time.Now().Unix(), time.Now().Add(time.Minute * state.Config.CertRenewAfterMin).Unix()}
	//Create renewal info file as well.
	out, err := yaml.Marshal(renewinfo)
	if err != nil {
		log.Println(err)
	}
	err = currentCertDir.Put(ctx, RenewalfileName, out)
	if err != nil {
		log.Println(err)
	}
	state.RenewalInfoMutex.Lock()
	state.Renewalinfo[domain] = renewinfo
	state.RenewalInfoMutex.Unlock()
}

//Base Handler
func (state *RuntimeState) IndexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "To get certificate http://localhost:8080/cert/{domainname}")
}

//Create a yaml file in directory---Not used ...Instead used autocert Put function
func (state *RuntimeState) CreateRenewalInfoFile(yamlFilePath string, renewinfo RenewalInfo) {
	renewalInfofilePath := filepath.Join(yamlFilePath, RenewalfileName)
	out, err := yaml.Marshal(renewinfo)
	if err != nil {
		log.Println(err)
		return
	}
	err = ioutil.WriteFile(renewalInfofilePath, out, 0600)
	if err != nil {
		log.Println(err)
		return
	}
}
