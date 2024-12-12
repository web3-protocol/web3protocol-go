package web3protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/sirupsen/logrus"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	golanglru2 "github.com/hashicorp/golang-lru/v2/expirable"
)

type Client struct {
	Config *Config
	Logger *logrus.Logger
	
	// Cache for domain name resolution
	DomainNameResolutionCache *localCache

	// Resolve mode cache
	ResolveModeCache *golanglru2.LRU[ResolveModeCacheKey, ResolveMode]

	// Resource request mode : cache invalidation tracking
	ResourceRequestCachingTracker ResourceRequestCachingTracker
}

type ResolveModeCacheKey struct {
	ChainId         int
	ContractAddress common.Address
}

type DomainNameService string
const (
	DomainNameServiceENS  = "ens"
	DomainNameServiceW3NS = "w3ns"
)

type ResolveMode string
const (
	ResolveModeAuto             = "auto"
	ResolveModeManual           = "manual"
	ResolveModeResourceRequests = "resourceRequest"
)

type ContractCallMode string
const (
	ContractCallModeCalldata = "calldata"
	ContractCallModeMethod   = "method"
)

type ContractReturnProcessing string
const (
	// Expect the whole returned data to be ABI-encoded bytes. Decode.
	ContractReturnProcessingDecodeABIEncodedBytes = "decodeABIEncodedBytes"
	// JSON-encode the raw bytes of the returned data
	ContractReturnProcessingRawBytesJsonEncoded = "jsonEncodeRawBytes"
	// JSON-encode the different return values
	ContractReturnProcessingJsonEncodeValues = "jsonEncodeValues"
	// Expect a string as first return value, parse it as a dataUrl
	// ContractReturnProcessingDataUrl = "dataUrl" // To implement
	// Expect a return following the erc5219 spec, will decode it using this spec
	ContractReturnProcessingDecodeErc5219Request = "decodeErc5219Request"
)

// A raw splitting of the web3 URL parts
type ParsedWeb3Url struct {
	Protocol string
	Hostname string
	ChainId string

	// The PathQuery is the full path, including the Pathname and Query
	PathQuery string
	Path string
	Query string

	Fragment string
}

// This contains a web3:// URL parsed and ready to call the main smartcontract
type Web3URL struct {
	// The actual url string "web3://...."
	Url string
	// The request HTTP headers
	HttpHeaders map[string]string
	
	// A raw splitting of the web3 URL parts, to be used by the processing
	// You should not use this directly outside of this package
	UrlParts ParsedWeb3Url

	// If the host was a domain name, what domain name service was used?
	HostDomainNameResolver DomainNameService
	// Chain of the name resolution service
	HostDomainNameResolverChainId int

	// The contract address (after optional domain name resolution) that is going to be called,
	// and its chain location
	ContractAddress common.Address // actual address
	ChainId         int

	// The ERC-4804 resolve mode
	ResolveMode ResolveMode

	// How do we call the smartcontract
	// 'calldata' : We use a raw calldata
	// 'method': We use the specified method and method parameters
	ContractCallMode ContractCallMode
	// Attributes for ContractCallModeCalldata
	Calldata []byte
	// Attributes for ContractCallModeMethod
	MethodName      string
	MethodArgs      []abi.Type
	MethodArgValues []interface{}

	// How to process the return of the contract. See enum for doc
	ContractReturnProcessing ContractReturnProcessing
	// In case of contractReturnProcessing being decodeABIEncodedBytes,
	// this will set the mime type to return
	DecodedABIEncodedBytesMimeType string
	// In case of ContractReturnProcessing being jsonEncodeValues,
	// this will tell us how to ABI-decode the returned data
	JsonEncodedValueTypes []abi.Type
}

// This contains the result of a web3:// URL call : the parsed URL, the raw contract return,
// and the bytes output, HTTP code and headers for the browser.
type FetchedWeb3URL struct {
	// The web3 URL, parsed
	ParsedUrl *Web3URL

	// The raw data returned by the contract
	ContractReturn []byte

	// The processed output, to be returned by the browser
	Output io.Reader
	// The HTTP code to be returned by the browser
	HttpCode int
	// The HTTP headers to be returned by the browser
	HttpHeaders map[string]string
}

/**
 * You'll need to instantiate a client to make calls.
 */
func NewClient(config *Config) (client *Client) {
	client = &Client{
		Config: config,
		DomainNameResolutionCache: newLocalCache(time.Duration(config.NameAddrCacheDurationInMinutes)*time.Minute, 10*time.Minute),
		ResolveModeCache: golanglru2.NewLRU[ResolveModeCacheKey, ResolveMode](1000, nil, time.Duration(0)),
		Logger: logrus.New(),
	}
	client.ResourceRequestCachingTracker = NewResourceRequestCachingTracker(client)

	return
}

/**
 * The main function of the package.
 * For a given full web3:// url ("web3://xxxx"), returns a structure containing
 * the bytes output and the HTTP code and headers, as well as plenty of informations on
 * how the processing was done.
 */
func (client *Client) FetchUrl(url string, httpHeaders map[string]string) (fetchedUrl FetchedWeb3URL, err error) {
	// Parse the URL
	parsedUrl, err := client.ParseUrl(url, httpHeaders)
	if err != nil {
		fetchedUrl.ParsedUrl = &parsedUrl
		return
	}

	// Attempt to make a response right away, without a contract call : 
	// We can do it if we know the output has not changed (see ERC-7774 resource request caching)
	earlyFetchedUrl, success, err := client.AttemptEarlyResponse(&parsedUrl)
	if err != nil {
		fetchedUrl.ParsedUrl = &parsedUrl
		return
	}
	if success {
		return earlyFetchedUrl, nil
	}

	// Fetch the contract return data
	contractReturn, err := client.FetchContractReturn(&parsedUrl)
	if err != nil {
		fetchedUrl.ParsedUrl = &parsedUrl
		return
	}

	// Finally, process the returned data
	fetchedUrl, err = client.ProcessContractReturn(&parsedUrl, contractReturn)
	if err != nil {
		return
	}

	return
}

/**
 * Step 1 : Parse the URL and determine how we are going to call the main contract.
 */
func (client *Client) ParseUrl(url string, httpHeaders map[string]string) (web3Url Web3URL, err error) {
	web3Url.Url = url
	web3Url.HttpHeaders = httpHeaders

	// Check that the URL is ASCII only
	for i := 0; i < len(web3Url.Url); i++ {
		if web3Url.Url[i] > unicode.MaxASCII {
			return web3Url, &ErrorWithHttpCode{http.StatusBadRequest, "URL is invalid, contains non-ASCII characters"}
		}
	}

	// Parse the main structure of the URL
	web3UrlRegexp, err := regexp.Compile(`^(?P<protocol>[^:]+):\/\/(?P<hostname>[^:\/?#]+)(:(?P<chainId>[1-9][0-9]*))?(?P<pathQuery>(?P<path>\/[^?#]*)?([?](?P<query>[^#]*))?)?(#(?P<fragment>.*)?)?$`)
	if err != nil {
		return
	}
	matches := web3UrlRegexp.FindStringSubmatch(web3Url.Url)
	if len(matches) == 0 {
		return web3Url, &ErrorWithHttpCode{http.StatusBadRequest, "Invalid URL format"}
	}
	for i, name := range web3UrlRegexp.SubexpNames() {
		if name == "protocol" {
			web3Url.UrlParts.Protocol = matches[i]
		} else if name == "hostname" {
			web3Url.UrlParts.Hostname = matches[i]
		} else if name == "chainId" {
			web3Url.UrlParts.ChainId = matches[i]
		} else if name == "pathQuery" {
			web3Url.UrlParts.PathQuery = matches[i]
		} else if name == "path" {
			web3Url.UrlParts.Path = matches[i]
		} else if name == "query" {
			web3Url.UrlParts.Query = matches[i]
		} else if name == "fragment" {
			web3Url.UrlParts.Fragment = matches[i]
		}
	}

	// Protocol name: 1 name and alias supported
	if web3Url.UrlParts.Protocol != "web3" && web3Url.UrlParts.Protocol != "w3" {
		return web3Url, &ErrorWithHttpCode{http.StatusBadRequest, "Protocol name is invalid"}
	}

	// Default chain is ethereum mainnet
	// Check if we were explicitely asked to go to another chain
	web3Url.ChainId = 1
	if len(web3Url.UrlParts.ChainId) > 0 {
		chainId, err := strconv.Atoi(web3Url.UrlParts.ChainId)
		if err != nil {
			// Regexp should always get us valid numbers, but we could enter here if overflow
			return web3Url, &ErrorWithHttpCode{http.StatusBadRequest, fmt.Sprintf("Unsupported chain %v", web3Url.UrlParts.ChainId)}
		}
		web3Url.ChainId = chainId
	}

	// Check that we support the chain
	_, ok := client.Config.Chains[web3Url.ChainId]
	if !ok {
		return web3Url, &ErrorWithHttpCode{http.StatusBadRequest, fmt.Sprintf("Unsupported chain %v", web3Url.ChainId)}
	}

	// Main hostname : We determine if we need hostname resolution, and do it
	if common.IsHexAddress(web3Url.UrlParts.Hostname) {
		web3Url.ContractAddress = common.HexToAddress(web3Url.UrlParts.Hostname)
	} else {
		// Determine name suffix
		hostnameParts := strings.Split(web3Url.UrlParts.Hostname, ".")
		if len(hostnameParts) <= 1 {
			return web3Url, &ErrorWithHttpCode{http.StatusBadRequest, "Invalid contract address"}
		}
		nameServiceSuffix := hostnameParts[len(hostnameParts)-1]
		domainNameWithoutSuffix := strings.Join(hostnameParts[0:len(hostnameParts)-1], ".")

		if domainNameWithoutSuffix == "" {
			return web3Url, &ErrorWithHttpCode{http.StatusBadRequest, "Invalid domain name"}
		}

		// If the chain id was not explicitely requested on the URL, we will use the
		// "default home" chain id of the name resolution service
		// (e.g. 1 for .eth, 333 for w3q) as the target chain
		if len(web3Url.UrlParts.ChainId) == 0 {
			domainNameService := client.Config.GetDomainNameServiceBySuffix(nameServiceSuffix)
			if domainNameService == "" || client.Config.DomainNameServices[domainNameService].DefaultChainId == 0 {
				return web3Url, &ErrorWithHttpCode{http.StatusBadRequest, "Unsupported domain name service suffix: " + nameServiceSuffix}
			}
			web3Url.ChainId = client.Config.DomainNameServices[domainNameService].DefaultChainId
		}

		// We will use a nameservice in the current target chain
		web3Url.HostDomainNameResolverChainId = web3Url.ChainId

		domainNameService := client.Config.GetDomainNameServiceBySuffix(nameServiceSuffix)
		if domainNameService == "" {
			return web3Url, &ErrorWithHttpCode{http.StatusBadRequest, "Unsupported domain name service suffix: " + nameServiceSuffix}
		}
		chainConfig, _ := client.Config.Chains[web3Url.HostDomainNameResolverChainId]
		_, domainNameServiceSupportedInChain := chainConfig.DomainNameServices[domainNameService]
		if domainNameServiceSupportedInChain == false {
			return web3Url, &ErrorWithHttpCode{http.StatusBadRequest, "Unsupported domain name service suffix: " + nameServiceSuffix}
		}
		web3Url.HostDomainNameResolver = domainNameService

		// Make the domaine name resolution, cache it
		var addr common.Address
		var targetChain int
		var hit bool
		cacheKey := fmt.Sprintf("%v:%v", web3Url.HostDomainNameResolverChainId, web3Url.UrlParts.Hostname)
		if client.DomainNameResolutionCache != nil {
			addr, targetChain, hit = client.DomainNameResolutionCache.get(cacheKey)
		}
		if !hit {
			var err error
			addr, targetChain, err = client.getAddressFromNameServiceInclErc6821(web3Url.HostDomainNameResolverChainId, web3Url.UrlParts.Hostname)
			if err != nil {
				return web3Url, err
			}
			if client.DomainNameResolutionCache != nil {
				client.DomainNameResolutionCache.add(cacheKey, addr, targetChain)
			}
		}
		web3Url.ContractAddress = addr
		if targetChain > 0 {
			web3Url.ChainId = targetChain
		}

		_, ok = client.Config.Chains[web3Url.ChainId]
		if !ok {
			return web3Url, &ErrorWithHttpCode{http.StatusBadRequest, fmt.Sprintf("unsupported chain id: %v", web3Url.ChainId)}
		}
	}

	// Determine the web3 mode
	// 3 modes:
	// - Auto : we parse the path and arguments and send them
	// - Manual : we forward all the path & arguments as calldata
	// - ResourceRequest : we parse the path and arguments and send them
	// See if it is cached
	resolveModeCacheKey := ResolveModeCacheKey{web3Url.ChainId, web3Url.ContractAddress}
	resolveMode, resolveModeIsCached := client.ResolveModeCache.Get(resolveModeCacheKey)
	if resolveModeIsCached {
		web3Url.ResolveMode = resolveMode
	// Not cached: Call the resolveMode in the contract
	} else {
		resolveModeCalldata, err := methodCallToCalldata("resolveMode", []abi.Type{}, []interface{}{})
		if err != nil {
			return web3Url, err
		}
		resolveModeReturn, err := client.callContract(web3Url.ContractAddress, web3Url.ChainId, resolveModeCalldata)
		// Auto : exact match or empty bytes32 value or empty value (method does not exist or return nothing)
		// or execution reverted
		if len(resolveModeReturn) == 32 && common.Bytes2Hex(resolveModeReturn) == "6175746f00000000000000000000000000000000000000000000000000000000" ||
			len(resolveModeReturn) == 32 && common.Bytes2Hex(resolveModeReturn) == "0000000000000000000000000000000000000000000000000000000000000000" ||
			len(resolveModeReturn) == 0 ||
			err != nil {
			web3Url.ResolveMode = ResolveModeAuto
			// Manual : exact match
		} else if len(resolveModeReturn) == 32 && common.Bytes2Hex(resolveModeReturn) == "6d616e75616c0000000000000000000000000000000000000000000000000000" {
			web3Url.ResolveMode = ResolveModeManual
			// ResourceRequest : exact match
		} else if len(resolveModeReturn) == 32 && common.Bytes2Hex(resolveModeReturn) == "3532313900000000000000000000000000000000000000000000000000000000" {
			web3Url.ResolveMode = ResolveModeResourceRequests
			// Other cases (method returning non recognized value) : throw an error
		} else {
			return web3Url, &ErrorWithHttpCode{http.StatusBadRequest, "Unsupported resolve mode"}
		}

		// Cache the resolve mode
		client.ResolveModeCache.Add(resolveModeCacheKey, web3Url.ResolveMode)
	}

	// Then process the resolve-mode-specific parts
	if web3Url.ResolveMode == ResolveModeManual {
		err = client.parseManualModeUrl(&web3Url)
	} else if web3Url.ResolveMode == ResolveModeAuto {
		err = client.parseAutoModeUrl(&web3Url)
	} else if web3Url.ResolveMode == ResolveModeResourceRequests {
		err = client.parseResourceRequestModeUrl(&web3Url)
	}
	if err != nil {
		return
	}

	return
}

/**
 * Step 2: Attempt an early response which bypass a contract call.
 */
func (client *Client) AttemptEarlyResponse(web3Url *Web3URL) (fetchedWeb3Url FetchedWeb3URL, success bool, err error) {
	// If we are in resource request mode, we check if the resource request is cached
	if web3Url.ResolveMode == ResolveModeResourceRequests {
		return client.AttemptEarlyResourceRequestModeResponse(web3Url)
	}

	return fetchedWeb3Url, false, nil
}

/**
 * Step 3: Make the call to the main contract.
 */
func (client *Client) FetchContractReturn(web3Url *Web3URL) (contractReturn []byte, err error) {
	var calldata []byte

	// Compute the calldata
	calldata, err = web3Url.ComputeCalldata()
	if err != nil {
		return contractReturn, err
	}

	// Do the contract call
	contractReturn, err = client.callContract(web3Url.ContractAddress, web3Url.ChainId, calldata)
	if err != nil {
		return
	}

	if len(contractReturn) == 0 {
		return contractReturn, &ErrorWithHttpCode{http.StatusNotFound, "The contract returned no data (\"0x\").\n\nThis could be due to any of the following:\n  - The contract does not have the requested function,\n  - The parameters passed to the contract function may be invalid, or\n  - The address is not a contract."}
	}

	return
}

/**
 * Step 4 : Process the data returned by the main contract.
 */
func (client *Client) ProcessContractReturn(web3Url *Web3URL, contractReturn []byte) (fetchedWeb3Url FetchedWeb3URL, err error) {
	// Add link to the parsedUrl
	fetchedWeb3Url.ParsedUrl = web3Url
	// Init the maps
	fetchedWeb3Url.HttpHeaders = map[string]string{}

	if web3Url.ContractReturnProcessing == "" {
		err = errors.New("Missing ContractReturnProcessing field")
		return
	}

	// Returned data is ABI-encoded bytes: We decode them and return them
	if web3Url.ContractReturnProcessing == ContractReturnProcessingDecodeABIEncodedBytes {
		bytesType, _ := abi.NewType("bytes", "", nil)
		argsArguments := abi.Arguments{
			abi.Argument{Name: "", Type: bytesType, Indexed: false},
		}

		// Decode the ABI bytes
		unpackedValues, err := argsArguments.UnpackValues(contractReturn)
		if err != nil {
			return fetchedWeb3Url, &ErrorWithHttpCode{http.StatusBadRequest, "Unable to parse contract output"}
		}
		fetchedWeb3Url.Output = bytes.NewReader(unpackedValues[0].([]byte))
		fetchedWeb3Url.HttpCode = 200

		// If a MIME type was hinted, inject it
		if web3Url.DecodedABIEncodedBytesMimeType != "" {
			fetchedWeb3Url.HttpHeaders["Content-Type"] = web3Url.DecodedABIEncodedBytesMimeType
		}

		// We JSON encode the raw bytes of the returned data
	} else if web3Url.ContractReturnProcessing == ContractReturnProcessingRawBytesJsonEncoded {
		jsonEncodedOutput, err := json.Marshal([]string{fmt.Sprintf("0x%x", contractReturn)})
		if err != nil {
			return fetchedWeb3Url, err
		}
		fetchedWeb3Url.Output = bytes.NewReader(jsonEncodedOutput)
		fetchedWeb3Url.HttpCode = 200
		fetchedWeb3Url.HttpHeaders["Content-Type"] = "application/json"

		// Having a contract return signature, we ABI-decode it and return the result JSON-encoded
	} else if web3Url.ContractReturnProcessing == ContractReturnProcessingJsonEncodeValues {
		argsArguments := abi.Arguments{}
		for _, jsonEncodedValueType := range web3Url.JsonEncodedValueTypes {
			argsArguments = append(argsArguments, abi.Argument{Name: "", Type: jsonEncodedValueType, Indexed: false})
		}

		// Decode the ABI data
		unpackedValues, err := argsArguments.UnpackValues(contractReturn)
		if err != nil {
			return fetchedWeb3Url, &ErrorWithHttpCode{http.StatusBadRequest, "Unable to parse contract output"}
		}

		// Format the data
		formattedValues := make([]interface{}, 0)
		for i, arg := range argsArguments {
			// get the type of the return value
			formattedValue, err := JsonEncodeAbiTypeValue(arg.Type, unpackedValues[i])
			if err != nil {
				return fetchedWeb3Url, err
			}
			formattedValues = append(formattedValues, formattedValue)
		}

		// JSON encode the data
		jsonEncodedOutput, err := json.Marshal(formattedValues)
		if err != nil {
			return fetchedWeb3Url, err
		}
		fetchedWeb3Url.Output = bytes.NewReader(jsonEncodedOutput)
		fetchedWeb3Url.HttpCode = 200
		fetchedWeb3Url.HttpHeaders["Content-Type"] = "application/json"

		// The returned data come from contract implementing ERC5219, process it
	} else if web3Url.ContractReturnProcessing == ContractReturnProcessingDecodeErc5219Request {
		err = client.ProcessResourceRequestContractReturn(&fetchedWeb3Url, web3Url, contractReturn)
	}

	return
}

// If ContractCallMode is calldata, returned the stored calldata
// If ContractCallMode is method, compute and return it
func (web3Url *Web3URL) ComputeCalldata() (calldata []byte, err error) {

	// Contract call is specified with method and arguments, deduce the calldata from it
	if web3Url.ContractCallMode == ContractCallModeMethod {
		// Compute the calldata
		calldata, err = methodCallToCalldata(web3Url.MethodName, web3Url.MethodArgs, web3Url.MethodArgValues)
		if err != nil {
			return
		}

		// Contract call is specified with calldata directly
	} else if web3Url.ContractCallMode == ContractCallModeCalldata {
		calldata = web3Url.Calldata

		// Empty field: This should not happen
	} else {
		err = errors.New("ContractCallMode is empty")
	}

	return
}
