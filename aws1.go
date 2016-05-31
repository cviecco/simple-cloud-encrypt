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

// Need to modify this to use the metadata service? is kms regin independent? what about roles?
func getRegionString() (string, error) {
	return "us-east-1", nil
}

func ExampleKMS_Decrypt(regionString string, inCiphertextBlob []byte) {
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
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err.Error())
		return
	}

	// Pretty-print the response data.
	fmt.Println(resp)
}

func ExampleKMS_Encrypt(regionString string) []byte {
	svc := kms.New(session.New(&aws.Config{Region: aws.String(regionString)}))

	params := &kms.EncryptInput{
		//KeyId:     aws.String("KeyIdType"), // Required
		KeyId:     aws.String(key_arn),
		Plaintext: []byte("PAYLOAD"), // Required
		EncryptionContext: map[string]*string{
			"Key": aws.String("EncryptionContextValue"), // Required
			// More values...
		},
		GrantTokens: []*string{
			aws.String("GrantTokenType"), // Required
			// More values...
		},
	}
	resp, err := svc.Encrypt(params)

	if err != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err.Error())
		return nil
	}

	// Pretty-print the response data.
	fmt.Println(resp)
	//fmt.Println(params)
	return resp.CiphertextBlob
}

func main() {
	regionString, err := getRegionString()
	if err != nil {
		log.Fatal("Cannot get Region string")
	}
	sess := session.New(&aws.Config{Region: aws.String(regionString)})
	fmt.Printf("+%v", sess)
	// now wat... encrypt?
	//svc := kms.New(sess)
	cipherBlob := ExampleKMS_Encrypt(regionString)
	ExampleKMS_Decrypt(regionString, cipherBlob)
}
