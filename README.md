# go-acme-cert-manager

## How to build and run the application:



1. Build and run:
```
$ cd go-acme-cert-manager

//Run go build
$ go build

//Run the executable file generated by go build
$ sudo ./go-acme-cert-manager

```

On the host machine open browser and visit http://localhost:8080/cert/{domain} .


## Approach:

Requesting certificates from acme server is not implemented but assuming we have got certificate and implementing further steps.

The Certificate is stored in certs directory which is cache to get certs and renew them upon expiry.



## Cache Schema:

Cache is implemented as directory. All certificates will be in "certs" directory. When a request for certificate for new domain comes up. After getting the certificate, it creates a
new directory with domainname as directory name and stores the certificate there. We can also store private key.

The application stores renewal file which contains cert generation and expiration info.
(this file will be helpful to get the renewal state in case of server restart)



All the commented code in main function implements to get certificate to itself and automatic renewal after it expires(after renew timer(in autocert.Manager) count down is complemented)

To renewal itself, uncomment the section in main function and comment last line

## TODO:
1) Filename and domain name validiation.
2) Implement logic for getting certs from acme server by solving acme dns challenge.
3) Implement an interface with different DNS server APIs functionality which helps in solving dns challenge.
4) Implement an gRPC server which would allow other services to get TLS certs on demand. (Not sure if this works. But need to implement it).
5) Code Optimizations and other changes.
