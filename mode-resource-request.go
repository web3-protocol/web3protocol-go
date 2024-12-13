package web3protocol

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"errors"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/andybalholm/brotli"
	"github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
)


// Step 1 : Process the web3:// url
func (client *Client) parseResourceRequestModeUrl(web3Url *Web3URL) (err error) {

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
	pathnameParts := strings.Split(web3Url.UrlParts.Path, "/")
	pathnamePartsToSend := pathnameParts[1:]
	// Remove empty strings at the end (e.g. /boo///)
	for len(pathnamePartsToSend) > 0 && pathnamePartsToSend[len(pathnamePartsToSend)-1] == "" {
		pathnamePartsToSend = pathnamePartsToSend[:len(pathnamePartsToSend)-1]
	}
	// Now URI-percent-decode the parts
	for i, _ := range pathnamePartsToSend {
		decodedPart, err := url.PathUnescape(pathnamePartsToSend[i])
		if err != nil {
			return &Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: errors.New("Unable to URI-percent decode: " + pathnamePartsToSend[i])}
		}
		pathnamePartsToSend[i] = decodedPart
	}
	argValues = append(argValues, pathnamePartsToSend)

	// Process query
	params := []struct {
		Key   string
		Value string
	}{}
	parsedQuery, err := ParseQuery(web3Url.UrlParts.Query)
	if err != nil {
		return err
	}
	for _, queryParam := range parsedQuery {
		params = append(params, struct {
			Key   string
			Value string
		}{
			Key:   queryParam.Name,
			Value: queryParam.Value,
		})
	}
	argValues = append(argValues, params)
	web3Url.MethodArgValues = argValues

	// Contract return processing will be custom
	web3Url.ContractReturnProcessing = ContractReturnProcessingDecodeErc5219Request

	return
}

// Step 2 : Attempt early response
func (client *Client) AttemptEarlyResourceRequestModeResponse(web3Url *Web3URL) (fetchedWeb3Url FetchedWeb3URL, success bool, err error) {
	
	// Lookup if we have an chain caching tracker for the chain of the request
	chainCachingTracker, ok := client.ResourceRequestCachingTracker.GetChainCachingTracker(web3Url.ChainId)
	if ok {
		// Lookup if we have an entry in the caching tracker
		resourceCachingInfos, ok := chainCachingTracker.GetResourceCachingInfos(web3Url.ContractAddress, SerializeResourceRequestMethodArgValues(web3Url.MethodArgValues))
		if ok {
			// Make a lowercase version of the web3Url.HttpHeaders
			httpHeadersLowercase := make(map[string]string)
			for headerName, headerValue := range web3Url.HttpHeaders {
				httpHeadersLowercase[strings.ToLower(headerName)] = headerValue
			}

			// If the request is asking for an ETag check, and we have one, do it
			_, hasIfNoneMatchHeader := httpHeadersLowercase["if-none-match"]
			// Resource has not been modified
			if hasIfNoneMatchHeader && httpHeadersLowercase["if-none-match"] != "" && resourceCachingInfos.ETag != "" && httpHeadersLowercase["if-none-match"] == resourceCachingInfos.ETag {		
				// Add link to the parsedUrl
				fetchedWeb3Url.ParsedUrl = web3Url
				// Create a 304 response
				fetchedWeb3Url.HttpCode = http.StatusNotModified
				fetchedWeb3Url.HttpHeaders = make(map[string]string)
				fetchedWeb3Url.HttpHeaders["ETag"] = resourceCachingInfos.ETag
				fetchedWeb3Url.Output = strings.NewReader("")

				success = true
				return
			}
		}
	}

	return
}

// Step 4 : We have the contract return, process it
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
		return &Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: errors.New("Unable to parse contract output")}
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
	headers, ok := unpackedValues[2].([]struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	})
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
	// Custom reader, to handle ERC-7617 chunking
	fetchedWeb3Url.Output = &ResourceRequestReader{
		Client:         client,
		FetchedWeb3URL: fetchedWeb3Url,
		Chunk:          []byte(body),
		Cursor:         0,
		NextChunkUrl:   nextChunkUrl,
	}


	//
	// ERC-7618 : Handle the decompression of data, when Content-Encoding is provided
	//

	// Make a mapping of the lowercase headers name pointing to the original case
	headersLowercase := make(map[string]string)
	for headerName, _ := range fetchedWeb3Url.HttpHeaders {
		headersLowercase[strings.ToLower(headerName)] = headerName
	}

	// Do we have a content-encoding header?
	contentEncodingHeaderName, ok := headersLowercase["content-encoding"]
	if ok {
		// Gzip support
		if fetchedWeb3Url.HttpHeaders[contentEncodingHeaderName] == "gzip" {
			// Add the decompression reader
			decompressionReader, err := gzip.NewReader(fetchedWeb3Url.Output)
			if err != nil {
				return &Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: errors.New("Gzip decompression error: " + err.Error())}
			}
			fetchedWeb3Url.Output = decompressionReader
			// Add the error wrapper reader
			fetchedWeb3Url.Output = &PrefixDecompressionErrorReader{Reader: fetchedWeb3Url.Output}

			// Remove the content-encoding header
			delete(fetchedWeb3Url.HttpHeaders, contentEncodingHeaderName)

			// Brotli support
		} else if fetchedWeb3Url.HttpHeaders[contentEncodingHeaderName] == "br" {
			// Add the decompression reader
			decompressionReader := brotli.NewReader(fetchedWeb3Url.Output)
			fetchedWeb3Url.Output = decompressionReader
			// Add the error wrapper reader
			fetchedWeb3Url.Output = &PrefixDecompressionErrorReader{Reader: fetchedWeb3Url.Output}

			// Remove the content-encoding header
			delete(fetchedWeb3Url.HttpHeaders, contentEncodingHeaderName)
		}
	}


	//
	// ERC-7774 : Cache Invalidation
	//

	// Get the cache control header directives
	cacheControlHeaderDirectives := map[string]string{}
	cacheControlLowercaseHeaderName, ok := headersLowercase["cache-control"]
	if ok {
		cacheControlHeaderDirectives = GetCacheControlHeaderDirectives(fetchedWeb3Url.HttpHeaders[cacheControlLowercaseHeaderName])
	}
	// Check if there is the "evm-events" cache control header directive
	evmEventDirectiveValue, hasEvmEventsDirective := cacheControlHeaderDirectives["evm-events"]
	// If so, we will process the caching headers
	if hasEvmEventsDirective {

		// Check if there is an ETag header
		etagLowercaseHeaderName, eTagHeaderPresent := headersLowercase["etag"]
		if eTagHeaderPresent {
			// Cache clearing event : the contract where it should come from, and the pathQuery it should
			// listen for
			// By default : the same contract address than the one serving the page, and the same pathQuery
			cacheClearingContractAddress := web3Url.ContractAddress
			cacheClearingPathQuery := SerializeResourceRequestMethodArgValues(web3Url.MethodArgValues)

			// By default, we will listen for cache clearing events from the same contract for the same path
			// But this can be overriden by the directive value
			// If there is a directive value, parse it
			// The format is : "<contractAddress><pathQuery>"
			var invalidDirectiveValueSyntax bool
			if evmEventDirectiveValue != "" {
				// If the directive value starts with "0x", it must start with a contract address
				if evmEventDirectiveValue[0:2] == "0x" && len(evmEventDirectiveValue) >= 42 {
					// Parse the contract address
					if common.IsHexAddress(evmEventDirectiveValue[:42]) == false {
						invalidDirectiveValueSyntax = true
					}
					cacheClearingContractAddress = common.HexToAddress(evmEventDirectiveValue[:42])
					// The rest is the path query
					evmEventDirectiveValue = evmEventDirectiveValue[42:]
				}
				// If the directive value is not empty, it must start with a "/"
				if evmEventDirectiveValue != "" {
					if evmEventDirectiveValue[0:1] != "/" {
						invalidDirectiveValueSyntax = true
					}
					cacheClearingPathQuery = evmEventDirectiveValue
				}
			}

			// Ensure that the syntax of the value was correct
			if invalidDirectiveValueSyntax == false {
				// Set the resource caching infos
				chainCachingTracker := client.ResourceRequestCachingTracker.GetOrCreateChainCachingTracker(web3Url.ChainId)
				// Get or create the resourceCachingInfos
				resourceCachingInfos, ok := chainCachingTracker.GetResourceCachingInfos(web3Url.ContractAddress, SerializeResourceRequestMethodArgValues(web3Url.MethodArgValues))
				if !ok {
					resourceCachingInfos = &ResourceCachingInfos{}
				}
				// Set the ETag
				resourceCachingInfos.ETag = fetchedWeb3Url.HttpHeaders[etagLowercaseHeaderName]
				// Save it
				serializedPathQuery := SerializeResourceRequestMethodArgValues(web3Url.MethodArgValues)
				chainCachingTracker.SetResourceCachingInfos(
					web3Url.ContractAddress, 
					serializedPathQuery,
					resourceCachingInfos)
				// Log
				client.Logger.WithFields(logrus.Fields{
					"domain": "resourceRequestModeCaching",
					"chain": web3Url.ChainId,
					"contractAddress": web3Url.ContractAddress,
					"etag": resourceCachingInfos.ETag,
					"listeners": resourceCachingInfos.CacheClearEventListeners,
				}).Info("Cache infos set for path ", serializedPathQuery)

				// If there is a different cache clearing contract address or path, we will update its resourceCachingInfos
				if cacheClearingContractAddress != web3Url.ContractAddress || cacheClearingPathQuery != SerializeResourceRequestMethodArgValues(web3Url.MethodArgValues) {
					// Get or create the resourceCachingInfos
					clearingResourceCachingInfos, ok := chainCachingTracker.GetResourceCachingInfos(cacheClearingContractAddress, cacheClearingPathQuery)
					if !ok {
						clearingResourceCachingInfos = &ResourceCachingInfos{}
						chainCachingTracker.SetResourceCachingInfos(
							cacheClearingContractAddress,
							cacheClearingPathQuery,
							clearingResourceCachingInfos,
						)
					}

					// Append ourselves to the CacheClearEventListeners. Ensure that there are no duplicates
					exists := false
					for _, location := range clearingResourceCachingInfos.CacheClearEventListeners {
						if location.ContractAddress == web3Url.ContractAddress && location.PathQuery == SerializeResourceRequestMethodArgValues(web3Url.MethodArgValues) {
							exists = true
							break
						}
					}
					if !exists {
						clearingResourceCachingInfos.CacheClearEventListeners = append(clearingResourceCachingInfos.CacheClearEventListeners, AddressPathQuery{
							ContractAddress: web3Url.ContractAddress,
							PathQuery:       SerializeResourceRequestMethodArgValues(web3Url.MethodArgValues),
						})
						// Log
						client.Logger.WithFields(logrus.Fields{
							"domain": "resourceRequestModeCaching",
							"chain": web3Url.ChainId,
							"contractAddress": cacheClearingContractAddress,
							"etag": clearingResourceCachingInfos.ETag,
							"listeners": clearingResourceCachingInfos.CacheClearEventListeners,
						}).Info("Added listener for cache infos for path ", cacheClearingPathQuery)
					}
				}
			}
		}

	}

	return
}

type ResourceRequestReader struct {
	Client         *Client
	FetchedWeb3URL *FetchedWeb3URL
	// Content of the last chunk call
	Chunk        []byte
	Cursor       int
	NextChunkUrl string
}

// Return the result of the method call
// Implements ERC-7617: Support for chunking
func (rrr *ResourceRequestReader) Read(p []byte) (readBytes int, err error) {
	// Still bytes to return in the current body chunk? Return it.
	if rrr.Cursor < len(rrr.Chunk) {
		remainingSize := len(rrr.Chunk) - rrr.Cursor

		if len(p) >= remainingSize {
			copy(p, rrr.Chunk[rrr.Cursor:])
			readBytes = remainingSize
			rrr.Cursor += readBytes
		} else {
			copy(p, rrr.Chunk[rrr.Cursor:rrr.Cursor+len(p)])
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
	nextChunkParsedUrl, err := rrr.Client.ParseUrl(rrr.NextChunkUrl, map[string]string{})
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

	// ERC-7617: Support for chunking
	// Find next chunk in headers
	rrr.NextChunkUrl = ""
	headers, ok := unpackedValues[2].([]struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	})
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

type PrefixDecompressionErrorReader struct {
	Reader io.Reader
}

func (r *PrefixDecompressionErrorReader) Read(p []byte) (readBytes int, err error) {
	readBytes, err = r.Reader.Read(p)
	if err != nil {
		// The brotli libs prefix his errors with "brotli: ": Put a little more helpful error message
		if strings.HasPrefix(err.Error(), "brotli: ") {
			err = &Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: errors.New("Brotli decompression error: " + strings.TrimPrefix(err.Error(), "brotli: "))}
		}
	}

	return
}

