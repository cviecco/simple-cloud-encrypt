package main

import (
	"crypto/rand"
	"crypto/sha512"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

var debug = false

// Need to modify this to use the metadata service? is kms regin independent? what about roles?
func getRegionString() (string, error) {
	svc := ec2metadata.New(session.New())
	region, err := svc.Region()
	return region, err
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
func KMS_Encrypt(regionString string, keyId string, plaintext []byte) (output []byte, err error) {
	svc := kms.New(session.New(&aws.Config{Region: aws.String(regionString)}))

	params := &kms.EncryptInput{
		KeyId:     aws.String(keyId),
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

func GenRandomKey(regionString string, KeyId string) (output []byte, err error) {
	// Since we are paranoid, we do not want to trust the KMS completely for our randomness, nor
	// trust the running vm for the randomness, so we do the following:
	// get 128 bytes* of randomness from both KMS and localmachine,
	// and for the secret the SHA512 of the concatenation of the KMS value with the localvalue
	//
	// *128 is the minumium value for KMS GenerateDataKeyInput.
	const numBytesPerInput = 128

	svc := kms.New(session.New(&aws.Config{Region: aws.String(regionString)}))
	// Seems like I cannot call kms.GenerateRandomInput without some extra policies... to simply policies we will
	// be using GenerateDataKeyInput instead
	params := &kms.GenerateDataKeyInput{
		KeyId: aws.String(KeyId), // Required
		EncryptionContext: map[string]*string{
			"Key": aws.String("EncryptionContextValue"), // Required
			// More values...
		},
		GrantTokens: []*string{
			aws.String("GrantTokenType"), // Required
			// More values...
		},
		//KeySpec: aws.String(keySpec),
		NumberOfBytes: aws.Int64(numBytesPerInput),
	}
	resp, err := svc.GenerateDataKey(params)
	if err != nil {
		return nil, err
	}
	if debug {
		// Pretty-print the response data.
		fmt.Println(resp)
	}

	// get some local randomness
	localRand := make([]byte, numBytesPerInput)
	_, err = rand.Read(localRand)
	if err != nil {
		//fmt.Println("error:", err)
		return nil, err
	}
	if debug {
		// Pretty-print localRand data.
		fmt.Println(localRand)
	}
	//append and hash
	localRand = append(localRand, resp.CiphertextBlob...)
	newRand := sha512.Sum512(localRand)
	output = newRand[:]
	return output, nil

}

func loadBytesFromFile(filename string) (output []byte, err error) {
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	inText, err := ioutil.ReadAll(f)
	if err != nil {
		log.Fatal(err)
	}
	// now wat... encrypt?
	//svc := kms.New(sess)
	if debug {
		fmt.Println(inText)
	}
	return inText, nil
}

func main() {
	var infilename = flag.String("infilename", "in.txt", "Input filename")
	var outfilename = flag.String("outfilename", "out.txt", "Output filename")
	var decrypt = flag.Bool("d", false, "Decrypt (defaults to encrypt)")
	var generate = flag.Bool("g", false, "Generate secure random data (64bytes)")
	var keyId = flag.String("keyid", "alias/testkey1", "Key to use in the form of a full arn(arnd:aws....) or alias(alias/testkey1)")
	flag.BoolVar(&debug, "D", false, "Enable Debug output")
	flag.Parse()

	//Sanity Checks/ select operation
	if *decrypt && *generate {
		log.Fatal("Cannot decrypt and Generate, choose only one")
	}
	regionString, err := getRegionString()
	if err != nil {
		log.Fatal("Cannot get Region string")
	}
	if debug {
		fmt.Printf("Region=%s\n", regionString)
	}

	var outText []byte

	switch {
	case *generate:
		if debug {
			fmt.Printf("Doing generation\n")
		}
		generatedBlob, err := GenRandomKey(regionString, *keyId)
		if err != nil {
			fmt.Println(err.Error())
			log.Fatal("Cannot generate random data")
		}
		outText = generatedBlob
	case !*decrypt: //encrypt
		if debug {
			fmt.Printf("Doing encryption\n")
		}
		inText, err := loadBytesFromFile(*infilename)
		if err != nil {
			log.Fatal(err)
		}
		cipherBlob, err := KMS_Encrypt(regionString, *keyId, inText)
		if err != nil {
			fmt.Println(err.Error())
			log.Fatal("Cannot encrypt Data")
		}
		outText = cipherBlob
	case *decrypt:
		if debug {
			fmt.Printf("Doing decryption\n")
		}
		inText, err := loadBytesFromFile(*infilename)
		if err != nil {
			log.Fatal(err)
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
