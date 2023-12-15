package web3protocol

import (
		"net/url"
		"strings"
		"net/http"
		"fmt"
		"io"
		"strconv"

		"github.com/ethereum/go-ethereum/accounts/abi"
)

// Step 1 : Process the web3:// url
func (client *Client) parseResourceRequestModeUrl(web3Url *Web3URL, urlMainParts map[string]string) (err error) {

		// For this mode, we call a specific function
		web3Url.ContractCallMode = ContractCallModeMethod
		web3Url.MethodName = "request"
		// Input types
		stringArrayType, _ := abi.NewType("string[]", "", nil)
		keyValueStructArrayType, _ := abi.NewType("tuple[]", "", []abi.ArgumentMarshaling{
				{Name: "key", Type: "string"},
				{Name: "value", Type: "string"},
		})
		web3Url.MethodArgs = []abi.Type{
				stringArrayType,
				keyValueStructArrayType,
		}

		// Extract the values we will feed to the contract
		argValues := make([]interface{}, 0)
		
		// Process path
		pathnameParts := strings.Split(urlMainParts["pathname"], "/")
		pathnamePartsToSend := pathnameParts[1:]
		// Remove empty strings at the end (e.g. /boo///)
		for len(pathnamePartsToSend) > 0 && pathnamePartsToSend[len(pathnamePartsToSend) - 1] == "" {
				pathnamePartsToSend = pathnamePartsToSend[:len(pathnamePartsToSend) - 1]
		}
		// Now URI-percent-decode the parts
		for i, _ := range pathnamePartsToSend {
				decodedPart, err := url.PathUnescape(pathnamePartsToSend[i])
				if err != nil  {
						return &ErrorWithHttpCode{http.StatusBadRequest, "Unable to URI-percent decode: " + pathnamePartsToSend[i]}
				}
				pathnamePartsToSend[i] = decodedPart
		}
		argValues = append(argValues, pathnamePartsToSend)
		
		// Process query
		params := []struct{
				Key string
				Value string}{}
		parsedQuery, err := ParseQuery(urlMainParts["searchParams"])
		if err != nil {
				return err
		}
		for _, queryParam := range parsedQuery {
				params = append(params, struct{
						Key string
						Value string}{
						Key: queryParam.Name,
						Value: queryParam.Value,
				})
		}
		argValues = append(argValues, params)
		web3Url.MethodArgValues = argValues

		// Contract return processing will be custom
		web3Url.ContractReturnProcessing = ContractReturnProcessingDecodeErc5219Request

		return
}

// Step 3 : We have the contract return, process it
func (client *Client) ProcessResourceRequestContractReturn(fetchedWeb3Url *FetchedWeb3URL, web3Url *Web3URL, contractReturn []byte) (err error) {

		// Preparing the ABI data structure with which we will decode the contract output
		uint16Type, _ := abi.NewType("uint16", "", nil)
		stringType, _ := abi.NewType("string", "", nil)
		keyValueStructArrayType, _ := abi.NewType("tuple[]", "", []abi.ArgumentMarshaling{
				{Name: "key", Type: "string"},
				{Name: "value", Type: "string"},
		})
		returnDataArgTypes := abi.Arguments{
				{Type: uint16Type},
				{Type: stringType},
				{Type: keyValueStructArrayType},
		}

		// Decode the ABI data
		unpackedValues, err := returnDataArgTypes.UnpackValues(contractReturn)
		if err != nil {
				return &ErrorWithHttpCode{http.StatusBadRequest, "Unable to parse contract output"}
		}

		// Assign the decoded data to the right slots
		// HTTP code
		httpCode, ok := unpackedValues[0].(uint16)
		if !ok {
				err = fmt.Errorf("invalid statusCode(uint16) %v", unpackedValues[0])
				return
		}
		fetchedWeb3Url.HttpCode = int(httpCode)
		
		// Headers
		nextChunkUrl := ""
		headers, ok := unpackedValues[2].([]struct{
				Key string `json:"key"`
				Value string `json:"value"`})
		if !ok {
				err = fmt.Errorf("invalid headers %v", unpackedValues[2])
				return
		}
		for _, header := range headers {
			// Special header, pointer to next chunk
			if header.Key == "web3-next-chunk" {
				nextChunkUrl = header.Value
			} else {
				fetchedWeb3Url.HttpHeaders[header.Key] = header.Value
			}
		}

		// Body
		body, ok := unpackedValues[1].(string)
		if !ok {
				err = fmt.Errorf("invalid body(string) %v", unpackedValues[1])
				return
		}
		// Custom reader, to handle the fetching of various chunks
		fetchedWeb3Url.Output = &ResourceRequestReader{
			Client: client,
			FetchedWeb3URL: fetchedWeb3Url,
			Chunk: []byte(body),
			Cursor: 0,
			NextChunkUrl: nextChunkUrl,
		}

		return
}

type ResourceRequestReader struct {
	Client *Client
	FetchedWeb3URL *FetchedWeb3URL
	// Content of the last chunk call
	Chunk []byte
	Cursor int
	NextChunkUrl string
}

func (rrr *ResourceRequestReader) Read(p []byte) (readBytes int, err error) {
	// Still bytes to return in the current body chunk? Return it.
	if rrr.Cursor < len(rrr.Chunk) {
		remainingSize := len(rrr.Chunk) - rrr.Cursor
		
		if len(p) >= remainingSize {
			copy(p, rrr.Chunk[rrr.Cursor:])
			readBytes = remainingSize
			rrr.Cursor += readBytes
		} else {
			copy(p, rrr.Chunk[rrr.Cursor:rrr.Cursor + len(p)])
			readBytes = len(p)
			rrr.Cursor += readBytes
		}

		return
	}

	// No more bytes to return in the current body chunk

	// No more chunk, return
	if rrr.NextChunkUrl == "" {
		return 0, io.EOF
	}

	// If URL is relative, make it absolute
	if rrr.NextChunkUrl[0:1] == "/" {
		rrr.NextChunkUrl = "web3://" + rrr.FetchedWeb3URL.ParsedUrl.ContractAddress.Hex() + ":" + strconv.Itoa(rrr.FetchedWeb3URL.ParsedUrl.ChainId) + rrr.NextChunkUrl
	}

	// Fetch the URL
	nextChunkParsedUrl, err := rrr.Client.ParseUrl(rrr.NextChunkUrl)
	if err != nil {
		return 0, err
	}
	// Fetch the contract return data
	nextChunkContractReturn, err := rrr.Client.FetchContractReturn(&nextChunkParsedUrl)
	if err != nil {
		return 0, err
	}

	// Preparing the ABI data structure with which we will decode the contract output
	uint16Type, _ := abi.NewType("uint16", "", nil)
	stringType, _ := abi.NewType("string", "", nil)
	keyValueStructArrayType, _ := abi.NewType("tuple[]", "", []abi.ArgumentMarshaling{
			{Name: "key", Type: "string"},
			{Name: "value", Type: "string"},
	})
	returnDataArgTypes := abi.Arguments{
			{Type: uint16Type},
			{Type: stringType},
			{Type: keyValueStructArrayType},
	}

	// Decode the ABI data
	unpackedValues, err := returnDataArgTypes.UnpackValues(nextChunkContractReturn)
	if err != nil {
			return 0, err
	}

	// Get body
	body, ok := unpackedValues[1].(string)
	if !ok {
			return 0, err
	}
	rrr.Chunk = []byte(body)
	rrr.Cursor = 0

	// Find next chunk in headers
	rrr.NextChunkUrl = ""
	headers, ok := unpackedValues[2].([]struct{
			Key string `json:"key"`
			Value string `json:"value"`})
	if !ok {
			return 0, err
	}
	for _, header := range headers {
		if header.Key == "web3-next-chunk" {
			rrr.NextChunkUrl = header.Value
		}
	}

	return rrr.Read(p)
}