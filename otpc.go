// otpc is a command-line OTP client that handles standard HOTP and TOTP tokens.
package main

import (
	"encoding/base32"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/gokyle/readpass"
	"github.com/gokyle/twofactor"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func errorf(m string, args ...interface{}) {
	m = "[!] " + m
	if m[len(m)-1] != '\n' {
		m += "\n"
	}
	fmt.Fprintf(os.Stderr, m, args...)
}

// account name -> url
var accounts = map[string]string{}

var passphrase []byte

func openFile(filename string) {
	fileData, err := decryptFile(filename)
	if err != nil {
		errorf("Failed to open accounts file: %v", err)
		os.Exit(1)
	}

	err = json.Unmarshal(fileData, &accounts)
	if err != nil {
		errorf("Failed to open accounts file: %v", err)
		os.Exit(1)
	}
}

func saveFile(filename string) {
	encoded, err := json.Marshal(accounts)
	if err != nil {
		errorf("Failed to serialise accounts: %v", err)
		os.Exit(1)
	}

	err = encryptFile(filename, encoded)
	if err != nil {
		errorf("%v", err)
		os.Exit(1)
	}
}

func listLabels(filename string) {
	openFile(filename)
	fmt.Println("Accounts:")
	for label := range accounts {
		fmt.Printf("\t%s\n", label)
	}
}

const (
	HOTP = iota + 1
	TOTP
	GoogleTOTP
)

func addAccount(label string, otpType int) {
	if accounts[label] != "" {
		errorf("warning: label %s exists with url %s", label, accounts[label])
	}

	// Default prompt is echoing, which we want here.
	secret, err := readpass.DefaultPasswordPrompt("Secret: ")
	if err != nil {
		errorf("Failed to read password.")
		os.Exit(1)
	}
	secret = sanitiseSecret(secret)

	switch otpType {
	case HOTP:
		in, err := readpass.DefaultPasswordPrompt("Initial counter (0): ")
		if err != nil {
			errorf("%v", err)
			os.Exit(1)
		}
		if in == "" {
			in = "0"
		}
		d, err := strconv.Atoi(in)
		if err != nil {
			errorf("%v", err)
			os.Exit(1)
		}

		in, err = readpass.DefaultPasswordPrompt("Digits (6 or 8): ")
		if err != nil {
			errorf("%v", err)
			os.Exit(1)
		}

		digits, err := strconv.Atoi(in)
		if err != nil {
			errorf("%v", err)
			os.Exit(1)
		}

		key, err := base32.StdEncoding.DecodeString(secret)
		if err != nil {
			errorf("%v", err)
			os.Exit(1)
		}

		var hotp *twofactor.HOTP
		hotp = twofactor.NewHOTP(key, uint64(d), digits)
		fmt.Printf("Confirmation: %s\n", hotp.OTP())
		secret = hotp.URL(label)
	case TOTP:
		in, err := readpass.DefaultPasswordPrompt("Time step (30s): ")
		if err != nil {
			errorf("%v", err)
			os.Exit(1)
		}
		if in == "" {
			in = "30s"
		}
		d, err := time.ParseDuration(in)
		if err != nil {
			errorf("%v", err)
			os.Exit(1)
		}

		in, err = readpass.DefaultPasswordPrompt("Digits (6 or 8): ")
		if err != nil {
			errorf("%v", err)
			os.Exit(1)
		}

		digits, err := strconv.Atoi(in)
		if err != nil {
			errorf("%v", err)
			os.Exit(1)
		}

		key, err := base32.StdEncoding.DecodeString(secret)
		if err != nil {
			errorf("%v", err)
			os.Exit(1)
		}

		var totp *twofactor.TOTP
		totp = twofactor.NewTOTPSHA1(key, 0, uint64(d.Seconds()), digits)
		fmt.Printf("Confirmation: %s\n", totp.OTP())
		secret = totp.URL(label)
	case GoogleTOTP:
		var totp *twofactor.TOTP
		totp, err = twofactor.NewGoogleTOTP(secret)
		if err != nil {
			errorf("%v", err)
			os.Exit(1)
		}
		fmt.Printf("Confirmation: %s\n", totp.OTP())
		secret = totp.URL(label)
	default:
		errorf("unrecognised OTP type")
		os.Exit(1)
	}
	accounts[label] = secret
}

func addNewAccount(filename string, label string, t int) {
	if _, err := os.Stat(filename); err != nil && !os.IsNotExist(err) {
		errorf("Failed to open account store: %v", err)
		os.Exit(1)
	} else if err == nil {
		openFile(filename)
	}

	addAccount(label, t)
	saveFile(filename)
}

func printTOTP(label string, otp twofactor.OTP) {
	fmt.Println(otp.OTP())
	for {
		for {
			t := time.Now()
			if t.Second() == 0 {
				break
			} else if t.Second() == 30 {
				break
			}
			<-time.After(1 * time.Second)
		}
		fmt.Println(otp.OTP())
		<-time.After(30 * time.Second)
	}
}

func sanitiseSecret(in string) string {
	in = strings.ToUpper(in)
	in = strings.Replace(in, " ", "", -1)
	if len(in)%8 != 0 {
		padding := 8 - (len(in) % 8)
		for i := 0; i < padding; i++ {
			in += "="
		}
	}
	return in
}

func exportDatabase(filename, outFile string) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		errorf("%v", err)
		os.Exit(1)
	}

	p := &pem.Block{
		Type:  "OTPC ACCOUNT STORE",
		Bytes: data,
	}

	var out io.Writer
	if outFile == "-" {
		out = os.Stdout
	} else {
		out, err = os.Create(outFile)
		if err != nil {
			errorf("%v", err)
			os.Exit(1)
		}
	}
	fmt.Fprintf(out, "%s\n", string(pem.EncodeToMemory(p)))
}

func importDatabase(filename, inFile string) {
	var dataFile io.Reader
	var err error
	if inFile == "-" {
		dataFile = os.Stdin
	} else {
		dataFile, err = os.Open(inFile)
		if err != nil {
			errorf("%v", err)
			os.Exit(1)
		}
	}

	pemData, err := ioutil.ReadAll(dataFile)
	if err != nil {
		errorf("%v", err)
		os.Exit(1)
	}
	p, _ := pem.Decode(pemData)
	if p == nil {
		errorf("No PEM data found.")
		os.Exit(1)
	} else if p.Type != "OTPC ACCOUNT STORE" {
		errorf("Invalid PEM type.")
		os.Exit(1)
	}

	err = ioutil.WriteFile(filename, p.Bytes, 0600)
	if err != nil {
		errorf("%v", err)
		os.Exit(1)
	}
}

func main() {
	baseFile := filepath.Join(os.Getenv("HOME"), ".otpc.db")
	fileName := flag.String("f", baseFile, "path to account store")
	otpType := flag.String("type", "google", "type of OTP")
	addNew := flag.Bool("new", false, "add a new account")
	doExport := flag.Bool("export", false, "export database in PEM format to stdout")
	doImport := flag.Bool("import", false, "import database from PEM format")
	showList := flag.Bool("list", false, "list accounts in database")
	flag.Parse()

	if *doExport || *doImport {
		if flag.NArg() != 1 {
			errorf("Need the PEM file specified as an argument.")
			os.Exit(1)
		}
		if *doExport {
			exportDatabase(*fileName, flag.Arg(0))
		} else {
			importDatabase(*fileName, flag.Arg(0))
		}
		os.Exit(0)
	} else if *showList {
		listLabels(*fileName)
		os.Exit(0)
	}

	if flag.NArg() == 0 {
		errorf("No label provided.")
		os.Exit(1)
	}
	label := flag.Arg(0)
	defer zero(passphrase)

	if *addNew {
		var t int
		switch *otpType {
		case "google":
			t = GoogleTOTP
		case "hotp":
			t = HOTP
		case "totp":
			t = TOTP
		default:
			errorf("Unsupported OTP type: %s", *otpType)
			os.Exit(1)
		}
		addNewAccount(*fileName, label, t)
	} else {
		openFile(*fileName)
		otp, label, err := twofactor.FromURL(accounts[label])
		if err != nil {
			errorf("Invalid OTP: %v", err)
			os.Exit(1)
		}
		switch otp.Type() {
		case twofactor.OATH_TOTP:
			printTOTP(label, otp)
		default:
			errorf("unknown OTP type")
			os.Exit(1)
		}
	}
}
