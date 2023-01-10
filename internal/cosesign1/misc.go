package cosesign1

//	Little handy utilities that make logging and a command line tool easier.

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/veraison/go-cose"
)

// Type to replace the rand.Reader with a source of fixed salt.
// Can be provided to the cose.Sign1 method instead of rand.Reader such that
// the signature is deterministic for testing and debugging purposes.
type fixedReader struct {
	valueToReturn byte
}

func (fr *fixedReader) Read(p []byte) (int, error) {
	if len(p) > 0 {
		p[0] = fr.valueToReturn
		return 1, nil
	}
	return 0, nil
}

func NewFixedReader(value byte) io.Reader {
	return &fixedReader{valueToReturn: value}
}

func WriteBlob(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}

func WriteString(path string, str string) error {
	var data = []byte(str)
	return WriteBlob(path, data)
}

func x509ToBase64(cert *x509.Certificate) string {
	base64Cert := base64.StdEncoding.EncodeToString(cert.Raw)

	return base64Cert
}

func keyToBase64(key any) string {
	derKey, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return ""
	}
	base64Key := base64.StdEncoding.EncodeToString(derKey)

	return base64Key
}

// Convertx509ToPEM creates a PEM from input cert in the form:
//
//	-----BEGIN CERTIFICATE-----
//	single line base64 standard encoded raw DER certificate
//	-----END CERTIFICATE-----
//
// Note that there are no extra line breaks added and that a string compare will
// need to accommodate that.
func Convertx509ToPEM(cert *x509.Certificate) string {
	base64Cert := x509ToBase64(cert)
	return base64CertToPEM(base64Cert)
}

func base64CertToPEM(base64Cert string) string {
	begin := "-----BEGIN CERTIFICATE-----\n"
	end := "\n-----END CERTIFICATE-----"

	pemData := begin + base64Cert + end

	return pemData
}

// StringToAlgorithm returns cose.Algorithm code corresponding to algorithm name.
func StringToAlgorithm(algoType string) (algo cose.Algorithm, err error) {
	switch algoType {
	case "PS256":
		algo = cose.AlgorithmPS256
	case "PS384":
		algo = cose.AlgorithmPS384
	case "PS512":
		algo = cose.AlgorithmPS512
	case "ES256":
		algo = cose.AlgorithmES256
	case "ES384":
		algo = cose.AlgorithmES384
	case "ES512":
		algo = cose.AlgorithmES512
	case "EdDSA":
		algo = cose.AlgorithmEd25519
	default:
		return 0, fmt.Errorf("unknown cose.Algorithm type %q", algoType)
	}
	return algo, err
}
