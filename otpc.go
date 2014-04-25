// otpc is a command-line OTP client that handles standard HOTP and TOTP tokens.
package main

import (
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
	secret = strings.Replace(strings.ToUpper(secret), " ", "", -1)

	switch otpType {
	case HOTP:
		errorf("Unsupported")
		os.Exit(1)
	case TOTP:
		errorf("Unsupported")
		os.Exit(1)
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

func main() {
	baseFile := filepath.Join(os.Getenv("HOME"), ".otpc.db")
	fileName := flag.String("f", baseFile, "path to account store")
	otpType := flag.String("type", "google", "type of OTP")
	addNew := flag.Bool("new", false, "add a new account")
	doExport := flag.Bool("export", false, "export database in PEM format to stdout")
	flag.Parse()

	if *doExport {
		if flag.NArg() != 1 {
			errorf("Need one output file specified as an argument.")
			os.Exit(1)
		}
		exportDatabase(*fileName, flag.Arg(0))
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
