package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

//next is the key arn
const key_arn = "arn:aws:kms:us-east-1:686559647175:key/ade6e070-2366-475d-ba2f-8a4ec9a96a9e"

var debug = true

// Need to modify this to use the metadata service? is kms regin independent? what about roles?
func getRegionString() (string, error) {
	return "us-east-1", nil
}

func KMS_Decrypt(regionString string, inCiphertextBlob []byte) (plaintext []byte, err error) {
	svc := kms.New(session.New(&aws.Config{Region: aws.String(regionString)}))

	params := &kms.DecryptInput{
		//CiphertextBlob: []byte("PAYLOAD"), // Required
		CiphertextBlob: inCiphertextBlob,
		EncryptionContext: map[string]*string{
			"Key": aws.String("EncryptionContextValue"), // Required
			// More values...
		},
		GrantTokens: []*string{
			aws.String("GrantTokenType"), // Required
			// More values...
		},
	}
	resp, err := svc.Decrypt(params)

	if err != nil {
		return nil, err
	}

	// Pretty-print the response data.
	if debug {
		fmt.Println(resp)
	}
	return resp.Plaintext, nil
}

/// The outputata here contains metadata required for decryption
func KMS_Encrypt(regionString string, plaintext []byte) (output []byte, err error) {
	svc := kms.New(session.New(&aws.Config{Region: aws.String(regionString)}))

	params := &kms.EncryptInput{
		KeyId:     aws.String(key_arn),
		Plaintext: plaintext,
		EncryptionContext: map[string]*string{
			"Key": aws.String("EncryptionContextValue"), // Required
		},
		GrantTokens: []*string{
			aws.String("GrantTokenType"), // Required
		},
	}
	resp, err := svc.Encrypt(params)

	if err != nil {
		return nil, err
	}

	// Pretty-print the response data.
	if debug {
		fmt.Println(resp)
	}
	return resp.CiphertextBlob, nil
}

func main() {
	var infilename = flag.String("infilename", "in.txt", "Input filename")
	var outfilename = flag.String("outfilename", "out.txt", "Output filename")
	var decrypt = flag.Bool("d", false, "Decrypt (defaults to encrypt)")
	flag.BoolVar(&debug, "-D", false, "Enable Debug output")
	flag.Parse()
	//infilename := "foo.txt"
	f, err := os.Open(*infilename)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	inText, err := ioutil.ReadAll(f)
	if err != nil {
		log.Fatal(err)
	}

	regionString, err := getRegionString()
	if err != nil {
		log.Fatal("Cannot get Region string")
	}
	// now wat... encrypt?
	//svc := kms.New(sess)
	if debug {
		fmt.Println(inText)
	}
	var outText []byte
	if !*decrypt {
		if debug {
			fmt.Printf("Doing encryption\n")
		}
		cipherBlob, err := KMS_Encrypt(regionString, inText)
		if err != nil {
			fmt.Println(err.Error())
			log.Fatal("Cannot encrypt Data")
		}
		outText = cipherBlob
	} else {
		if debug {
			fmt.Printf("Doing decryption\n")
		}
		plaintext, err := KMS_Decrypt(regionString, inText)
		if err != nil {
			fmt.Println(err.Error())
			log.Fatal("Cannot decrypt Data")
		}

		outText = plaintext
	}
	if debug {
		fmt.Println(outText)
	}
	//outfilename := "out.txt"
	err = ioutil.WriteFile(*outfilename, outText, 0600)
	if err != nil {
		log.Fatal(err)
	}
}
