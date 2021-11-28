package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
)

// Certificates struct which contains
// an array of certificates
type Certificates struct {
	Certificates []Certificate `json:"certificates"`
}

// Certificate struct which contains a name
// a type and a list of social links
type Certificate struct {
	Name string `json:"name"`
}

type CertificateJSON struct {
	Algorythm    string     `json:"algorythm"`
	SerialNumber string     `json:"serialNumber"`
	Bits         string     `json:"bits"`
	CN           string     `json:"cn"`
	NotAfter     string     `json:"notAfter"`
	NotBefore    string     `json:"notBefore"`
	O            string     `json:"o"`
	SelfSigned   string     `json:"selfSigned"`
	IssuerJSON   IssuerJSON `json:"issuer"`
	Type         string     `json:"type"`
	Status       string     `json:"status"`
}

type IssuerJSON struct {
	CO  string  `json:"co"`
	O   string  `json:"o"`
	Key KeyJSON `json:"key"`
}

type KeyJSON struct {
	Type         string            `json:"type"`
	SHA256       string            `json:"sha256"`
	Certificates []CertificateJSON `json:"certificates"`
}

type DataJSON struct {
	Certificates []CertificateJSON `json:"certificates"`
}

func openFileInByte(fileName string) ([]byte, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func decodePemCertificate(pemCertificate []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemCertificate)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing the certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func main() {
	// Open our jsonFile
	jsonFile, err := os.Open("./go/certificates.json")
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("Successfully Opened certificates.json")
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()

	// read our opened xmlFile as a byte array.
	byteValue, _ := ioutil.ReadAll(jsonFile)

	// we initialize our Certificates array
	var certificates []Certificate

	// we unmarshal our byteArray which contains our
	// jsonFile's content into 'certificates' which we defined above
	json.Unmarshal(byteValue, &certificates)

	var keyMap = make(map[string]KeyJSON)

	// we iterate through every user within our certificates array and
	// print out the user Type, their name, and their facebook url
	// as just an example
	for i := 0; i < len(certificates); i++ {
		fmt.Println("Pem: " + certificates[i].Name)

		var fileName = "./static/certs/" + certificates[i].Name + ".pem"

		JsonCertificate := CertificateJSON{}

		fmt.Println("----------")
		fmt.Println(fileName)
		pemCertificate, err := openFileInByte(fileName)

		if err != nil {
			fmt.Println(err)
			continue
		}

		cert, err := decodePemCertificate(pemCertificate)

		if err != nil {
			fmt.Println(err)
			continue
		}

		der := cert.Raw
		//pem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

		//fmt.Println("Pem: " + string(pem))

		algorythm := cert.SignatureAlgorithm
		fmt.Println("Algorythm: " + algorythm.String())

		isRSA := cert.PublicKeyAlgorithm == x509.RSA
		isECDSA := cert.PublicKeyAlgorithm == x509.ECDSA

		var key KeyJSON

		if isRSA {
			fmt.Println("PublicKey: ")

			rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)
			fmt.Println(rsaPublicKey.N)
			fmt.Println(rsaPublicKey.E)

			SubjectPublicKeyInfo := cert.RawSubjectPublicKeyInfo
			SubjectPublicKeyInfoSha256 := sha256.Sum256(SubjectPublicKeyInfo)

			sha256 := fmt.Sprintf("%x", SubjectPublicKeyInfoSha256)
			fmt.Println("SubjectPublicKeyInfoSha256: " + sha256)

			crtsh := "https://crt.sh/?spkisha256=" + sha256
			fmt.Println("crtsh other certificates signed with that key: " + crtsh)

			key.Type = "RSA"
			key.SHA256 = sha256

		} else if isECDSA {
			params := cert.PublicKey.(*ecdsa.PublicKey).Curve.Params()
			fmt.Println("Curve: ")
			fmt.Println(params)

			curve := params.Name
			fmt.Println(curve)

			x := cert.PublicKey.(*ecdsa.PublicKey).X.String()
			y := cert.PublicKey.(*ecdsa.PublicKey).Y.String()
			fmt.Println("X: " + x)
			fmt.Println("Y: " + y)

			SubjectPublicKeyInfo := cert.RawSubjectPublicKeyInfo
			SubjectPublicKeyInfoSha256 := sha256.Sum256(SubjectPublicKeyInfo)

			sha256 := fmt.Sprintf("%x", SubjectPublicKeyInfoSha256)
			fmt.Println("SubjectPublicKeyInfoSha256: " + sha256)

			crtsh := "https://crt.sh/?spkisha256=" + sha256
			fmt.Println("crtsh other certificates signed with that key: " + crtsh)

			key.Type = "ECDSA"
			key.SHA256 = sha256

		} else {
			fmt.Println("Unknown algorythm")
		}

		cn := cert.Subject.CommonName
		fmt.Println("Common Name: " + cn)

		JsonCertificate.CN = cn

		serial := cert.SerialNumber
		fmt.Println("Serial: " + serial.String())

		JsonCertificate.SerialNumber = serial.String()

		notAfter := cert.NotAfter
		fmt.Println("Not After: " + notAfter.String())

		JsonCertificate.NotAfter = notAfter.String()

		notBefore := cert.NotBefore
		fmt.Println("Not Before: " + notBefore.String())

		JsonCertificate.NotBefore = notBefore.String()

		o := cert.Subject.Organization[0]
		fmt.Println("Organization: " + o)

		JsonCertificate.O = o

		selfSigned := cert.IsCA
		fmt.Println("Self Signed: " + strconv.FormatBool(selfSigned))

		issuer := cert.Issuer
		fmt.Println("Issuer: " + issuer.String())

		sha256 := sha256.Sum256(der)
		fmt.Println("SHA256: " + fmt.Sprintf("%x", sha256))

		crtsh := "https://crt.sh/?q=" + fmt.Sprintf("%x", sha256)
		fmt.Println("crtsh: " + crtsh)

		JsonCertificate.IssuerJSON.CO = issuer.CommonName
		JsonCertificate.IssuerJSON.O = issuer.Organization[0]

		certificateSignature := cert.Signature
		fmt.Println("Certificate Signature: ")
		fmt.Println(certificateSignature)
		//JsonCertificate.IssuerJSON.Key.SHA256 =

		if val, ok := keyMap[key.SHA256]; ok {
			key = val
		} else {
			key.Certificates = append(key.Certificates, JsonCertificate)
			keyMap[key.SHA256] = key
		}

	}

	keys := make([]KeyJSON, 0, len(keyMap))
	for _, v := range keyMap {
		keys = append(keys, v)
	}

	jsonFormatted, _ := json.MarshalIndent(keys, "", "  ")

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(jsonFormatted))

	// open the file for writing
	file, _ := os.Create("./static/testgo.json")
	// close the file
	defer file.Close()

	// write the data to the file
	file.WriteString(string(jsonFormatted))
}
