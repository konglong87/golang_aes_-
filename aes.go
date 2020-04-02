package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

//AesEncrypt aes加密
func AesEncrypt(origData, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)

	pass64 := base64.StdEncoding.EncodeToString(crypted)
	return pass64, nil
}

//AesDecrypt aes解密
func AesDecrypt(cryptedPlaint string, key []byte) (string, error) {
	crypted, err:= base64.StdEncoding.DecodeString(cryptedPlaint)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return string(origData), nil
}

func main() {
	var aeskey = []byte("890883191387831973281786d9876345") //秘钥
	passText := []byte("123") //明文
	xpass, err := AesEncrypt(passText, aeskey)
	if err != nil {
		fmt.Println("[err1]",err)
		return
	}

	fmt.Println("加密后==>",xpass)

	tpass, err3 := AesDecrypt(xpass, aeskey)
	if err3 != nil {
		fmt.Println(err3)
		return
	}
	fmt.Println("解密后==>", tpass)
}
