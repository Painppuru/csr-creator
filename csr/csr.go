package csr

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"time"
)

// variable to add E-Mail address to the CSR
var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

// Struct to store all the CSR Info
type CSRInfo struct {
	Country      string
	Province     string
	Locality     string
	Organization string
	CommonName   string
	SAN          []string
	Email        string
	Password     string
	IPAddress    []net.IP
	PrivateKey   *rsa.PrivateKey
}

// function to check if the provided string is allready listed in the array
func (csr *CSRInfo) SanContains(check string) bool {
	for _, v := range csr.SAN {
		if check == v {
			return true
		}
	}
	return false
}

// function to create the CSR
func (csrInfo *CSRInfo) CreateCsr() {
	csrInfo.CreatePrivateKey()

	subj := pkix.Name{
		CommonName:   csrInfo.CommonName,
		Country:      []string{csrInfo.Country},
		Province:     []string{csrInfo.Province},
		Locality:     []string{csrInfo.Locality},
		Organization: []string{csrInfo.Organization},
		ExtraNames: []pkix.AttributeTypeAndValue{
			{
				Type: oidEmailAddress,
				Value: asn1.RawValue{
					Tag:   asn1.TagIA5String,
					Bytes: []byte(csrInfo.Email),
				},
			},
		},
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
		DNSNames:           csrInfo.SAN,
		IPAddresses:        csrInfo.IPAddress,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, csrInfo.PrivateKey)
	if err != nil {
		fmt.Println("The following Error occured: ", err)
		os.Exit(1)
	}
	_ = os.Mkdir("./csr", os.ModePerm)
	csrFileName := fmt.Sprintf("./csr/%v_%v.csr", time.Now().Format("20060102150405"), csrInfo.CommonName)

	csr, err := os.Create(csrFileName)
	if err != nil {
		fmt.Println("The following Error occured: ", err)
		os.Exit(1)
	}
	defer csr.Close()
	pem.Encode(csr, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	csrInfo.ExportPrivateKey()
}

// function to create a Private Key for the CSR
func (csrInfo *CSRInfo) CreatePrivateKey() {
	var err error
	csrInfo.PrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("The following Error occured: ", err)
		os.Exit(1)
	}
}

// function to export the Private key
func (csrInfo *CSRInfo) ExportPrivateKey() {
	_ = os.Mkdir("./keys", os.ModePerm)

	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(csrInfo.PrivateKey),
	}

	if csrInfo.Password != "" {
		var err error
		block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(csrInfo.Password), x509.PEMCipherAES256)
		if err != nil {
			fmt.Println("The following Error occured: ", err)
			os.Exit(1)
		}
	}
	keyFileName := fmt.Sprintf("./keys/%v_%v.key", time.Now().Format("20060102150405"), csrInfo.CommonName)
	pkey, err := os.Create(keyFileName)
	if err != nil {
		fmt.Println("The following Error occured: ", err)
		os.Exit(1)
	}
	defer pkey.Close()
	pkey.Write(pem.EncodeToMemory(block))

}
