package web3protocol

import (
	"mime"
	"strings"
)

func (client *Client) parseManualModeUrl(web3Url *Web3URL) (err error) {
	// Path must be at least "/"
	path := web3Url.UrlParts.PathQuery
	if len(path) == 0 {
		path = "/"
	}

	web3Url.ContractCallMode = ContractCallModeCalldata
	web3Url.Calldata = []byte(path)
	web3Url.ContractReturnProcessing = ContractReturnProcessingDecodeABIEncodedBytes

	// Default MIME type is text/html
	web3Url.DecodedABIEncodedBytesMimeType = "text/html"
	// The path can contain an extension, which will override the mime type to use
	pathnameParts := strings.Split(web3Url.UrlParts.Path, ".")
	if len(pathnameParts) > 1 {
		// If no mime type is found, this will return empty string
		web3Url.DecodedABIEncodedBytesMimeType = mime.TypeByExtension("." + pathnameParts[len(pathnameParts)-1])
	}

	return
}
