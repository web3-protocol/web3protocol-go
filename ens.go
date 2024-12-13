package web3protocol

import (
	// "context"
	"fmt"
	"errors"
	// "mime"
	"net/http"
	"strings"

	// "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	// "github.com/ethereum/go-ethereum/crypto"

	// log "github.com/sirupsen/logrus"
	"golang.org/x/net/idna"

	"golang.org/x/crypto/sha3"
)

type ArgInfo struct {
	methodSignature string
	mimeType        string
	calldata        string
}

var (
	EmptyString  = strings.Repeat("0", 62) + "20" + strings.Repeat("0", 64)
	EmptyAddress = strings.Repeat("0", 64)

	p = idna.New(idna.MapForLookup(), idna.StrictDomainName(false), idna.Transitional(false))
)

// Normalize normalizes a name according to the ENS rules
func Normalize(input string) (output string, err error) {
	output, err = p.ToUnicode(input)
	if err != nil {
		return
	}
	// If the name started with a period then ToUnicode() removes it, but we want to keep it
	if strings.HasPrefix(input, ".") && !strings.HasPrefix(output, ".") {
		output = "." + output
	}
	return
}

// LabelHash generates a simple hash for a piece of a name.
func LabelHash(label string) (hash [32]byte, err error) {
	normalizedLabel, err := Normalize(label)
	if err != nil {
		return
	}

	sha := sha3.NewLegacyKeccak256()
	if _, err = sha.Write([]byte(normalizedLabel)); err != nil {
		return
	}
	sha.Sum(hash[:0])
	return
}

// NameHash generates a hash from a name that can be used to
// look up the name in ENS
func NameHash(name string) (hash [32]byte, err error) {
	if name == "" {
		return
	}
	normalizedName, err := Normalize(name)
	if err != nil {
		return
	}
	parts := strings.Split(normalizedName, ".")
	for i := len(parts) - 1; i >= 0; i-- {
		if hash, err = nameHashPart(hash, parts[i]); err != nil {
			return
		}
	}
	return
}

func nameHashPart(currentHash [32]byte, name string) (hash [32]byte, err error) {
	sha := sha3.NewLegacyKeccak256()
	if _, err = sha.Write(currentHash[:]); err != nil {
		return
	}
	nameSha := sha3.NewLegacyKeccak256()
	if _, err = nameSha.Write([]byte(name)); err != nil {
		return
	}
	nameHash := nameSha.Sum(nil)
	if _, err = sha.Write(nameHash); err != nil {
		return
	}
	sha.Sum(hash[:0])
	return
}

// If the read is failed, the address will be read with the `addr` record
func (client *Client) getAddressFromNameService(nameServiceChain int, nameWithSuffix string) (common.Address, int, error) {
	if common.IsHexAddress(nameWithSuffix) {
		return common.HexToAddress(nameWithSuffix), 0, nil
	}

	// Not a domain name? It now has to have a dot to be a domain name, or it is just an invalid address
	if len(strings.Split(nameWithSuffix, ".")) == 1 {
		return common.Address{}, 0, &Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: errors.New("Unrecognized domain name")}
	}

	nsInfo, we := client.getConfigs(nameServiceChain, nameWithSuffix)
	if we != nil {
		return common.Address{}, 0, we
	}

	nameHash, _ := NameHash(nameWithSuffix)
	resolver, e := client.getResolver(nsInfo.ResolverAddress, nameHash, nameServiceChain, nameWithSuffix)
	if e != nil {
		return common.Address{}, 0, e
	}
	return client.resolve(nameServiceChain, resolver, nameHash)
}

// Resolve the address from the name service, including the ERC-6821 cross-chain resolution
func (client *Client) getAddressFromNameServiceInclErc6821(nameServiceChain int, nameWithSuffix string) (common.Address, int, error) {
	if common.IsHexAddress(nameWithSuffix) {
		return common.HexToAddress(nameWithSuffix), 0, nil
	}
	nsInfo, we := client.getConfigs(nameServiceChain, nameWithSuffix)
	if we != nil {
		return common.Address{}, 0, we
	}

	nameHash, _ := NameHash(nameWithSuffix)
	resolver, e := client.getResolver(nsInfo.ResolverAddress, nameHash, nameServiceChain, nameWithSuffix)
	if e != nil {
		return common.Address{}, 0, e
	}

	// ERC-6821: Cross-chain resolution
	if nsInfo.Id == DomainNameServiceENS {
		// Generating the calldata for the text(bytes32, string) call
		bytes32Type, _ := abi.NewType("bytes32", "", nil)
		stringType, _ := abi.NewType("string", "", nil)
		methodArgTypes := []abi.Type{bytes32Type, stringType}
		argValues := make([]interface{}, 0)
		argValues = append(argValues, nameHash)
		argValues = append(argValues, "contentcontract")
		msg, err := methodCallToCalldata("text", methodArgTypes, argValues)
		if err != nil {
			return common.Address{}, 0, err
		}

		// Call the contract
		bs, err := client.callContract(resolver, nameServiceChain, msg)
		if err != nil {
			return common.Address{}, 0, we
		}
		if common.Bytes2Hex(bs) != EmptyString {
			res, err := parseOutput(bs, "(string)")
			if err == nil {
				return client.parseChainSpecificAddress(res[0].(string))
			}
		}
	// W3NS: ERC-6821-like cross-chain resolution
	} else if nsInfo.Id == DomainNameServiceW3NS {
		// Generating the calldata for the webHandler(bytes32) call
		bytes32Type, _ := abi.NewType("bytes32", "", nil)
		methodArgTypes := []abi.Type{bytes32Type}
		argValues := make([]interface{}, 0)
		argValues = append(argValues, nameHash)
		msg, err := methodCallToCalldata("webHandler", methodArgTypes, argValues)
		if err != nil {
			return common.Address{}, 0, err
		}

		// Call the contract
		bs, err := client.callContract(resolver, nameServiceChain, msg)
		if err != nil {
			return common.Address{}, 0, we
		}
		if common.Bytes2Hex(bs) != EmptyString {
			res, err := parseOutput(bs, "(address)")
			if err == nil {
				return client.parseChainSpecificAddress(res[0].(string))
			}
		}
	}

	// If nothing, return the address
	return client.resolve(nameServiceChain, resolver, nameHash)
}

func (client *Client) resolve(nameServiceChain int, resolver common.Address, nameHash [32]byte) (common.Address, int, error) {
	// Generating the calldata for the addr(bytes32) call
	bytes32Type, _ := abi.NewType("bytes32", "", nil)
	methodArgTypes := []abi.Type{bytes32Type}
	argValues := make([]interface{}, 0)
	argValues = append(argValues, nameHash)
	msg, err := methodCallToCalldata("addr", methodArgTypes, argValues)
	if err != nil {
		return common.Address{}, 0, &Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: err}
	}

	// Call the contract
	bs, err := client.callContract(resolver, nameServiceChain, msg)
	if err != nil {
		return common.Address{}, 0, &Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: err}
	}
	if common.Bytes2Hex(bs) == EmptyAddress {
		return common.Address{}, 0, &Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: errors.New("Empty address")}
	}
	res, e := parseOutput(bs, "address")
	if e != nil {
		return common.Address{}, 0, e
	}
	return client.parseChainSpecificAddress(res[0].(string))
}

func (client *Client) getResolver(nsAddr common.Address, nameHash [32]byte, nameServiceChain int, nameWithSuffix string) (common.Address, error) {
	// Generating the calldata for the resolver(bytes32) call
	bytes32Type, _ := abi.NewType("bytes32", "", nil)
	methodArgTypes := []abi.Type{bytes32Type}
	argValues := make([]interface{}, 0)
	argValues = append(argValues, nameHash)
	msg, err := methodCallToCalldata("resolver", methodArgTypes, argValues)
	if err != nil {
		return common.Address{}, &Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: err}
	}

	// Call the contract
	bs, err := client.callContract(nsAddr, nameServiceChain, msg)
	if err != nil {
		return common.Address{}, &Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: err}
	}
	if common.Bytes2Hex(bs) == EmptyAddress {
		return common.Address{}, &Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: errors.New("Cannot resolve domain name")}
	}
	return common.BytesToAddress(bs), nil
}

func (client *Client) getConfigs(nameServiceChain int, nameWithSuffix string) (DomainNameServiceChainConfig, error) {
	ss := strings.Split(nameWithSuffix, ".")
	if len(ss) <= 1 {
		return DomainNameServiceChainConfig{}, &Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: errors.New("Invalid domain name: " + nameWithSuffix)}
	}
	suffix := ss[len(ss)-1]
	chainInfo, ok := client.Config.Chains[nameServiceChain]
	if !ok {
		return DomainNameServiceChainConfig{}, &Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: errors.New(fmt.Sprintf("unsupported chain: %v", nameServiceChain))}
	}
	domainNameService := client.Config.GetDomainNameServiceBySuffix(suffix)
	if domainNameService == "" {
		return DomainNameServiceChainConfig{}, &Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: errors.New("Unsupported domain name suffix: " + suffix)}
	}
	nsInfo, ok := chainInfo.DomainNameServices[domainNameService]
	if !ok {
		return DomainNameServiceChainConfig{}, &Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: errors.New("Unsupported domain name suffix: " + suffix)}
	}
	return nsInfo, nil
}

// support chainSpecificAddress from EIP-3770
func (client *Client) parseChainSpecificAddress(addr string) (common.Address, int, error) {
	if common.IsHexAddress(addr) {
		return common.HexToAddress(addr), 0, nil
	}
	ss := strings.Split(addr, ":")
	if len(ss) != 2 {
		return common.Address{}, 0, &Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: errors.New("invalid contract address from name service: " + addr)}
	}
	chainName := ss[0]
	chainId := client.Config.GetChainIdByShortName(strings.ToLower(chainName))
	if chainId == 0 {
		return common.Address{}, 0, &Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: errors.New("unsupported chain short name from name service: " + addr)}
	}
	if !common.IsHexAddress(ss[1]) {
		return common.Address{}, 0, &Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: errors.New("invalid contract address from name service: " + addr)}
	}
	return common.HexToAddress(ss[1]), chainId, nil
}

// parseOutput parses the bytes into actual values according to the returnTypes string
// TODO: To remove, legacy code
func parseOutput(output []byte, userTypes string) ([]interface{}, error) {
	returnTypes := "(bytes)"
	if userTypes == "()" {
		return []interface{}{"0x" + common.Bytes2Hex(output)}, nil
	} else if userTypes != "" {
		returnTypes = userTypes
	}
	returnArgs := strings.Split(strings.Trim(returnTypes, "()"), ",")
	var argsArray abi.Arguments
	for _, arg := range returnArgs {
		ty, err := abi.NewType(arg, "", nil)
		if err != nil {
			return nil, &Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: err}
		}
		argsArray = append(argsArray, abi.Argument{Name: "", Type: ty, Indexed: false})
	}
	var res []interface{}
	res, err := argsArray.UnpackValues(output)
	if err != nil {
		return nil, &Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: err}
	}
	if userTypes != "" {
		for i, arg := range argsArray {
			// get the type of the return value
			res[i], _ = JsonEncodeAbiTypeValue(arg.Type, res[i])
		}
	}
	return res, nil
}
