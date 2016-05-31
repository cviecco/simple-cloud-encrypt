package main

import (
	//"compress/gzip"
	//"io"
	"log"
	//"os"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	//"github.com/aws/aws-sdk-go/service/s3/s3manager"
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

/// The output data here contains metadata required for decryption
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
	regionString, err := getRegionString()
	if err != nil {
		log.Fatal("Cannot get Region string")
	}
	// now wat... encrypt?
	//svc := kms.New(sess)
	cipherBlob, err := KMS_Encrypt(regionString, []byte("Somedata here"))
	if err != nil {
		fmt.Println(err.Error())
		log.Fatal("Cannot encrypt Data")
	}
	plaintext, err := KMS_Decrypt(regionString, cipherBlob)
	if err != nil {
		log.Fatal("Cannot decrypt Data")
	}
	fmt.Println(plaintext)
}
