package web3protocol

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/naoina/toml"
	"github.com/stretchr/testify/assert"
)

type AbiType struct {
	Type       string
	Components []AbiType
}

// Mostly to workaround the fact that
// in TOML, array can't contain multiple types
type MethodValue struct {
	Value interface{}
}

type TestError struct {
	Label    string
	HttpCode int
}

type Test struct {
	Name string

	Error TestError

	Url string

	HostDomainNameResolver        DomainNameService
	HostDomainNameResolverChainId int

	ContractAddress common.Address
	ChainId         int

	ResolveMode      ResolveMode
	ContractCallMode ContractCallMode

	Calldata string

	MethodName      string
	MethodArgs      []AbiType
	MethodArgValues []MethodValue

	ContractReturnProcessing       ContractReturnProcessing
	DecodedABIEncodedBytesMimeType string
	JsonEncodedValueTypes          []AbiType

	ContractReturn string

	// Output as bytes ("0xabcdef" string)
	Output string
	// Output as string (for easier readibility)
	OutputAsString string
	HttpCode       int
	HttpHeaders    map[string]string
}

type TestGroup struct {
	Name      string
	Standards []string
	Tests     []Test
}

type TestType string

const (
	// We parse a web3:// URL
	TestTypeUrlParsing = "urlParsing"
	// We process data returned by a contract
	TestTypeContractReturnProcessing = "contractReturnProcessing"
	// Do the whole process and fetch an URL
	TestTypeFetch = "fetch"
)

type TestGroups struct {
	Name   string
	Type   TestType
	Groups map[string]TestGroup
	// Name2Chain      map[string]string
	// ChainConfigs    map[string]ChainConfig
}

func init() {

}

func TestSuite(t *testing.T) {
	// Prepare an hardcoded config for the tests
	config := Config{
		Chains: map[int]ChainConfig{
			1: ChainConfig{
				ChainId:   1,
				ShortName: "eth",
				RPC:       ChainRPCConfig{
					Url: "https://ethereum.publicnode.com/",
				},
				DomainNameServices: map[DomainNameService]DomainNameServiceChainConfig{
					DomainNameServiceENS: DomainNameServiceChainConfig{
						Id:              DomainNameServiceENS,
						ResolverAddress: common.HexToAddress("0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"),
					},
				},
			},
			5: ChainConfig{
				ChainId:   5,
				ShortName: "gor",
				RPC:       ChainRPCConfig{
					Url: "https://ethereum-goerli.publicnode.com",
				},
				DomainNameServices: map[DomainNameService]DomainNameServiceChainConfig{
					DomainNameServiceENS: DomainNameServiceChainConfig{
						Id:              DomainNameServiceENS,
						ResolverAddress: common.HexToAddress("0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"),
					},
				},
			},
			11155111: ChainConfig{
				ChainId:   11155111,
				ShortName: "sep",
				RPC:       ChainRPCConfig{
					Url: "https://ethereum-sepolia.publicnode.com",
				},
				DomainNameServices: map[DomainNameService]DomainNameServiceChainConfig{
					DomainNameServiceENS: DomainNameServiceChainConfig{
						Id:              DomainNameServiceENS,
						ResolverAddress: common.HexToAddress("0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"),
					},
				},
			},
			3334: ChainConfig{
				ChainId:   3334,
				ShortName: "w3q-g",
				RPC:       ChainRPCConfig{
					Url: "https://galileo.web3q.io:8545",
				},
				DomainNameServices: map[DomainNameService]DomainNameServiceChainConfig{
					DomainNameServiceW3NS: DomainNameServiceChainConfig{
						Id:              DomainNameServiceW3NS,
						ResolverAddress: common.HexToAddress("0xD379B91ac6a93AF106802EB076d16A54E3519CED"),
					},
				},
			},
			42170: ChainConfig{
				ChainId:   42170,
				ShortName: "arb-nova",
				RPC:       ChainRPCConfig{
					Url: "https://nova.arbitrum.io/rpc",
				},
			},
		},
		DomainNameServices: map[DomainNameService]DomainNameServiceConfig{
			DomainNameServiceENS: DomainNameServiceConfig{
				Id:             DomainNameServiceENS,
				Suffix:         "eth",
				DefaultChainId: 1,
			},
			DomainNameServiceW3NS: DomainNameServiceConfig{
				Id:             DomainNameServiceW3NS,
				Suffix:         "w3q",
				DefaultChainId: 333,
			},
		},
		NameAddrCacheDurationInMinutes: 60,
	}

	// Test files
	files := []string{
		"tests/parsing-base.toml",
		"tests/parsing-mode-manual.toml",
		"tests/parsing-mode-auto.toml",
		"tests/parsing-mode-resource-request.toml",
		"tests/contract-return-processing.toml",
		"tests/fetch.toml",
	}
	for _, file := range files {
		// Open test file
		f, err := os.Open(file)
		if err != nil {
			panic(err)
		}
		defer func(f *os.File) {
			err = f.Close()
		}(f)

		// Decode the test groups
		testGroups := TestGroups{}
		err = toml.NewDecoder(bufio.NewReader(f)).Decode(&testGroups)
		if _, ok := err.(*toml.LineError); ok {
			err = fmt.Errorf(file + ", " + err.Error())
			panic(err)
		}

		for _, testGroup := range testGroups.Groups {
			// We will only process some ERCs
			isStandardSupported := false
			for _, standard := range testGroup.Standards {
				if standard == "ERC-6860" || // Main, ERC-4804 clarified and modified
					standard == "ERC-6821" || // ENS name resolution
					standard == "ERC-6944" || // Resource request mode
					standard == "ERC-7087" || // MIME type for auto mode
					standard == "ERC-7617" || // Chunk support for resource request mode
					standard == "ERC-7618" { // Content-encoding for resource request mode
					isStandardSupported = true
				}
			}
			if isStandardSupported == false {
				continue
			}

			for _, test := range testGroup.Tests {
				testName := fmt.Sprintf("%v/%v/%v/%v", testGroups.Name, testGroup.Name, test.Name, test.Url)
				t.Run(testName, func(t *testing.T) {

					// Create a new web3:// client
					client := NewClient(&config)

					// Several types of tests
					// Test type: Parsing URL
					if testGroups.Type == TestTypeUrlParsing {
						// Parse the URL
						parsedUrl, err := client.ParseUrl(test.Url, map[string]string{})

						if err == nil {
							// If we were expecting an error, fail
							if test.Error.Label != "" || test.Error.HttpCode > 0 {
								assert.Fail(t, "An error was expected")
							}

							if test.ContractAddress.Hex() != "0x0000000000000000000000000000000000000000" {
								assert.Equal(t, test.ContractAddress, parsedUrl.ContractAddress)
							}
							if test.ChainId > 0 {
								assert.Equal(t, test.ChainId, parsedUrl.ChainId)
							}

							if test.HostDomainNameResolver != "" {
								assert.Equal(t, test.HostDomainNameResolver, parsedUrl.HostDomainNameResolver)
							}
							if test.HostDomainNameResolverChainId > 0 {
								assert.Equal(t, test.HostDomainNameResolverChainId, parsedUrl.HostDomainNameResolverChainId)
							}

							if test.ResolveMode != "" {
								assert.Equal(t, test.ResolveMode, parsedUrl.ResolveMode)
							}
							if test.ContractCallMode != "" {
								assert.Equal(t, test.ContractCallMode, parsedUrl.ContractCallMode)
							}

							if test.Calldata != "" {
								testCalldata, err := hexutil.Decode(test.Calldata)
								if err != nil {
									panic(err)
								}
								assert.Equal(t, testCalldata, parsedUrl.Calldata)
							}

							if test.MethodName != "" {
								assert.Equal(t, test.MethodName, parsedUrl.MethodName)
							}
							if len(test.MethodArgs) > 0 {
								assert.Equal(t, len(test.MethodArgs), len(parsedUrl.MethodArgs), "Unexpected number of arguments")
								for i, methodArg := range test.MethodArgs {
									expectedTypeStr := methodArg.Type
									// If a tuple : Determine "the unparsed string for
									// deriving signatures" to compare it
									if len(expectedTypeStr) >= 5 && expectedTypeStr[0:5] == "tuple" {
										components := []abi.ArgumentMarshaling{}
										for _, component := range methodArg.Components {
											components = append(components, abi.ArgumentMarshaling{
												Name: "xx", // This is necessary, or err
												Type: component.Type,
											})
										}
										tupleType, err := abi.NewType("tuple[]", "", components)
										if err != nil {
											panic(err)
										}
										expectedTypeStr = tupleType.String()
									}

									assert.Equal(t, expectedTypeStr, parsedUrl.MethodArgs[i].String())
								}
							}
							if len(test.MethodArgValues) > 0 {
								assert.Equal(t, len(test.MethodArgValues), len(parsedUrl.MethodArgValues), "Unexpected number of argument values")
								for i, methodArgValue := range test.MethodArgValues {
									switch methodArgValue.Value.(type) {
									// Convert into to bigint
									case int64:
										newValue := new(big.Int)
										newValue.SetInt64(methodArgValue.Value.(int64))
										methodArgValue.Value = newValue
									}
									// bytes<X>
									if len(test.MethodArgs[i].Type) > 5 && test.MethodArgs[i].Type[0:5] == "bytes" {
										methodArgValue.Value = common.HexToHash(methodArgValue.Value.(string))
									}
									switch test.MethodArgs[i].Type {
									case "bytes":
										methodArgValue.Value = common.FromHex(methodArgValue.Value.(string))
									case "address":
										methodArgValue.Value = common.HexToAddress(methodArgValue.Value.(string))
									case "string[]":
										argValue := []string{}
										for _, entry := range methodArgValue.Value.([]interface{}) {
											argValue = append(argValue, entry.(string))
										}
										methodArgValue.Value = argValue
									case "tuple[]":
										// Some hardcoding here, expecting
										// (string,string)[] and
										// with "Key" and "Value"
										// Will not work in other cases
										// To rework when necessary
										argValue := []struct{ Key, Value string }{}
										for _, entry := range methodArgValue.Value.([]interface{}) {
											newEntry := struct{ Key, Value string }{
												Key:   entry.([]interface{})[0].(string),
												Value: entry.([]interface{})[1].(string),
											}
											argValue = append(argValue, newEntry)
										}
										methodArgValue.Value = argValue
									}
									assert.Equal(t, methodArgValue.Value, parsedUrl.MethodArgValues[i])
								}
							}

							if test.ContractReturnProcessing != "" {
								assert.Equal(t, test.ContractReturnProcessing, parsedUrl.ContractReturnProcessing)
							}
							if test.DecodedABIEncodedBytesMimeType != "" {
								assert.Equal(t, test.DecodedABIEncodedBytesMimeType, parsedUrl.DecodedABIEncodedBytesMimeType)
							}
							if len(test.JsonEncodedValueTypes) > 0 {
								assert.Equal(t, len(test.JsonEncodedValueTypes), len(parsedUrl.JsonEncodedValueTypes), "Unexpected number of arguments")
								for i, JsonEncodedValueType := range test.JsonEncodedValueTypes {
									argMarshaling := testAbiTypeToAbiArgumentMarshaling(JsonEncodedValueType)
									abiType, err := abi.NewType(argMarshaling.Type, "", argMarshaling.Components)
									if err != nil {
										assert.Fail(t, "Unexpected error", err)
									}
									assert.Equal(t, abiType.String(), parsedUrl.JsonEncodedValueTypes[i].String())
								}
							}
						} else { // err != nil
							// If no error was expected, fail
							if test.Error.Label == "" && test.Error.HttpCode == 0 {
								assert.Fail(t, "Unexpected error", err)
							}

							if test.Error.Label != "" {
								assert.Equal(t, test.Error.Label, err.Error())
							}
							if test.Error.HttpCode > 0 {
								if web3Err, ok := err.(*ErrorWithHttpCode); ok {
									assert.Equal(t, test.Error.HttpCode, web3Err.HttpCode)
								} else {
									assert.Fail(t, "Error is unexpectly not a ErrorWithHttpCode", err)
								}
							}
						}

						// Test type: Contract return processing
					} else if testGroups.Type == TestTypeContractReturnProcessing {
						// Create and populate a Web3URL
						web3Url := Web3URL{
							ContractReturnProcessing:       test.ContractReturnProcessing,
							DecodedABIEncodedBytesMimeType: test.DecodedABIEncodedBytesMimeType,
							JsonEncodedValueTypes:          []abi.Type{},
						}
						for _, jsonEncodedValueType := range test.JsonEncodedValueTypes {
							abiType, err := abi.NewType(jsonEncodedValueType.Type, "", nil)
							if err != nil {
								assert.Fail(t, "Error while creating abi type: "+jsonEncodedValueType.Type)
							}
							web3Url.JsonEncodedValueTypes = append(web3Url.JsonEncodedValueTypes, abiType)
						}
						contractReturn := common.FromHex(test.ContractReturn)

						// Execute the processing
						fetchedWeb3Url, err := client.ProcessContractReturn(&web3Url, contractReturn)

						var output []byte
						if err == nil {
							output, err = ioutil.ReadAll(fetchedWeb3Url.Output)
						}

						if err == nil {
							// If we were expecting an error, fail
							if test.Error.Label != "" || test.Error.HttpCode > 0 {
								assert.Fail(t, "An error was expected")
							}
							if test.Output != "" {
								testOutput := common.FromHex(test.Output)
								assert.Equal(t, testOutput, output)
							}
							if test.OutputAsString != "" {
								assert.Equal(t, test.OutputAsString, string(output))
							}
							if test.HttpCode > 0 {
								assert.Equal(t, test.HttpCode, fetchedWeb3Url.HttpCode)
							}
							assert.Equal(t, len(test.HttpHeaders), len(fetchedWeb3Url.HttpHeaders), "Unexpected number of http headers")
							for i, httpHeader := range test.HttpHeaders {
								assert.Equal(t, httpHeader, fetchedWeb3Url.HttpHeaders[i])
							}
						} else { // err != nil
							// If no error was expected, fail
							if test.Error.Label == "" && test.Error.HttpCode == 0 {
								assert.Fail(t, "Unexpected error", err)
							}

							if test.Error.Label != "" {
								assert.Equal(t, test.Error.Label, err.Error())
							}
							if test.Error.HttpCode > 0 {
								if web3Err, ok := err.(*ErrorWithHttpCode); ok {
									assert.Equal(t, test.Error.HttpCode, web3Err.HttpCode)
								} else {
									assert.Fail(t, "Error is unexpectly not a ErrorWithHttpCode", err)
								}
							}
						}

						// Test type: Execution of the whole process
					} else if testGroups.Type == TestTypeFetch {
						// Fetch the url
						fetchedWeb3Url, err := client.FetchUrlDirect(test.Url, map[string]string{})

						if err == nil {
							// If we were expecting an error, fail
							if test.Error.Label != "" || test.Error.HttpCode > 0 {
								assert.Fail(t, "An error was expected")
							}

							output, err := ioutil.ReadAll(fetchedWeb3Url.Output)
							if err != nil {
								assert.Fail(t, "Error reading the output")
							}
							if test.Output != "" {
								testOutput := common.FromHex(test.Output)
								assert.Equal(t, testOutput, output)
							}
							if test.OutputAsString != "" {
								assert.Equal(t, test.OutputAsString, string(output))
							}
							if test.HttpCode > 0 {
								assert.Equal(t, test.HttpCode, fetchedWeb3Url.HttpCode)
							}
							assert.Equal(t, len(test.HttpHeaders), len(fetchedWeb3Url.HttpHeaders), "Unexpected number of http headers")
							for i, httpHeader := range test.HttpHeaders {
								assert.Equal(t, httpHeader, fetchedWeb3Url.HttpHeaders[i])
							}
						} else { // err != nil
							// If no error was expected, fail
							if test.Error.Label == "" && test.Error.HttpCode == 0 {
								assert.Fail(t, "Unexpected error", err)
							}

							if test.Error.Label != "" {
								assert.Equal(t, test.Error.Label, err.Error())
							}
							if test.Error.HttpCode > 0 {
								if web3Err, ok := err.(*ErrorWithHttpCode); ok {
									assert.Equal(t, test.Error.HttpCode, web3Err.HttpCode)
								} else {
									assert.Fail(t, "Error is unexpectly not a ErrorWithHttpCode", err)
								}
							}
						}
					}

				})
			}
		}
	}
}

// Convert a test AbiType to a go-ethereum abi.ArgumentMarshaling
// Recursive
func testAbiTypeToAbiArgumentMarshaling(abiType AbiType) (argMarshaling abi.ArgumentMarshaling) {
	argMarshaling.Type = abiType.Type
	argMarshaling.Name = "x"
	for _, component := range abiType.Components {
		argMarshaling.Components = append(argMarshaling.Components, testAbiTypeToAbiArgumentMarshaling(component))
	}

	return
}
