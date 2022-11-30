// go: generate goversioninfo -icon = icon_YOUR_GO_PROJECT.ico

package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	"csr-creator/csr"

	"golang.org/x/crypto/ssh/terminal"
)

// structure for the Error Mesage that gets printed out in the Console
type errorHandling struct {
	Message string
}

// function for the errorHandling structure that prints out the Message and waits for an input to exit the application
func (e errorHandling) write() {
	var input string
	fmt.Println(e.Message)
	fmt.Print("Press Enter to Exit the Application")
	// it needs 2 Scan calls to get a newline from before
	fmt.Scanln(&input)
	fmt.Scanln(&input)
	os.Exit(1)
}

// globale variable definition for regex and scanner
var ipRe *regexp.Regexp
var dnsRe *regexp.Regexp
var scanner *bufio.Scanner

// initialize the Regex and Scanner
func init() {
	ipRe = regexp.MustCompile(`^(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2}\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})$`)
	dnsRe = regexp.MustCompile(`^(?:[A-Za-z0-9\-\_\*]+\.)+[a-z]{2,}$`)
	scanner = bufio.NewScanner(os.Stdin)
}

func main() {
	var option int
	var csrInfo csr.CSRInfo

	fmt.Println("Welcome to the CSR Generator.")
	csrInfo.CommonName = getStdinString("What would be the Common Name: ")
	csrInfo.SAN = append(csrInfo.SAN, csrInfo.CommonName)

	subject(&csrInfo)

	fmt.Println("Which Certificate would you like to generate?")
	fmt.Println("1.\tSAN Fields without Password")
	fmt.Println("2.\tSAN Fields with Password")
	if _, err := os.Stat(".password"); err == nil {
		fmt.Println("3.\tSAN Fields with .password file")
	}
	getStdinInt("Option: ", &option)

	switch option {
	case 1:
		break
	case 2:
		fmt.Print("Password: ")
		password, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		fmt.Print("\n")
		if err != nil {
			e := errorHandling{Message: fmt.Sprintf("Couldn't get a password. The following error occurred: %v", err)}
			e.write()
		}
		csrInfo.Password = string(password)
	case 3:
		passwordFile, err := os.ReadFile(".password")
		if err != nil {
			e := errorHandling{Message: fmt.Sprintf("Couldn't open .password file in the current directory you are in. The following error occurred: %v", err)}
			e.write()
		}
		csrInfo.Password = string(passwordFile)
	}
	san(&csrInfo)

	csrInfo.CreateCsr()
}

// Function to get the SAN fields
func san(csrInfo *csr.CSRInfo) {
	c := make(chan string)
	q := make(chan string)

Loop:
	for {
		go sanInput(c, q)
		select {
		case field := <-c:
			if csrInfo.SanContains(field) {
				fmt.Printf("%s is allready in the SAN Fields.\n", field)
				continue
			}
			if dnsRe.MatchString(field) {
				csrInfo.SAN = append(csrInfo.SAN, field)
			} else if ipRe.MatchString(field) {
				csrInfo.IPAddress = append(csrInfo.IPAddress, net.ParseIP(field))
			} else {
				fmt.Println("The provided string isn't an IP or a DNS.")
			}

		case <-q:
			break Loop
		}
	}
}

// function to read the SAN fields from the CLi
func sanInput(c, q chan string) {
	var san string
	fmt.Print("SAN Field: ")
	_, err := fmt.Scanln(&san)
	if err != nil && strings.Compare("", san) == 0 {
		q <- "quit"
		return
	}
	c <- san
}

// Function to define the Subject for the certificate
func subject(csrInfo *csr.CSRInfo) {
	var option int
	fmt.Println("Do you want to use the default options for the subject")
	fmt.Println("1.\tUse the default values:")
	fmt.Println("\t\tCountry:\t")      //add Default value for Country
	fmt.Println("\t\tProvince:\t")     //add Default value for Province
	fmt.Println("\t\tLocality:\t")     //add Default value for Locality
	fmt.Println("\t\tOrganization:\t") //add Default value for Organization
	fmt.Println("\t\tE-Mail:\t\t")     //add Default value for Email
	fmt.Println("2.\tSet new values")

	getStdinInt("Number of the selected option: ", &option)

	switch option {
	case 1:
		csrInfo.Country = ""      //add Default value for Country
		csrInfo.Province = ""     //add Default value for Province
		csrInfo.Locality = ""     //add Default value for Locality
		csrInfo.Organization = "" //add Default value for Organization
		csrInfo.Email = ""        //add Default value for Email
	case 2:
		csrInfo.Country = getStdinString("Country: ")
		csrInfo.Province = getStdinString("Province: ")
		csrInfo.Locality = getStdinString("Locality: ")
		csrInfo.Organization = getStdinString("Organization: ")
		csrInfo.Email = getStdinString("Email: ")
	}
}

// function to read string input and do a correct error handling
func getStdinString(question string) string {
	var answer string
	scanner = bufio.NewScanner(os.Stdin)
	fmt.Print(question)
	if scanner.Scan() {
		answer = scanner.Text()
	}
	return answer
}

// function to read int input and do a correct error handling
func getStdinInt(question string, answer *int) {
	fmt.Print(question)
	_, err := fmt.Scanln(answer)
	if err != nil {
		e := errorHandling{Message: fmt.Sprintf("Cloudn't parse your input into a int. The following error occurred: %v", err.Error())}
		e.write()
	}
}
