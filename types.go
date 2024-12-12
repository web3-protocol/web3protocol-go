package web3protocol

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
)

// The config used by the client to make the web3:// calls
type Config struct {
	// A config per chain. Key is the chain id
	Chains map[int]ChainConfig

	// A config per domain name service. Key is their short name
	DomainNameServices map[DomainNameService]DomainNameServiceConfig

	// There is an internal domain name resolution cache
	NameAddrCacheDurationInMinutes int
}

func (config *Config) GetChainIdByShortName(shortName string) (result int) {
	for chainId, _ := range config.Chains {
		if config.Chains[chainId].ShortName == shortName {
			result = chainId
			break
		}
	}

	return
}
func (config *Config) GetDomainNameServiceBySuffix(suffix string) (result DomainNameService) {
	for domainNameService, _ := range config.DomainNameServices {
		if config.DomainNameServices[domainNameService].Suffix == suffix {
			result = domainNameService
			break
		}
	}

	return
}

type ChainConfig struct {
	ChainId int

	// A mapping of chain "short name" (from https://github.com/ethereum-lists/chains) to their chain id
	// Used by ERC-6821 which relies on ERC-3770 addresses
	ShortName string

	// The RPC URL to use to call the chain
	RPC string
	// The maximum number of parralel requests to the RPC
	RPCMaxConcurrentRequests int

	// A chain-specific config per domain name service. Key is their short name.
	DomainNameServices map[DomainNameService]DomainNameServiceChainConfig
}

// Attributes of a domain name service
type DomainNameServiceConfig struct {
	Id DomainNameService

	// "eth", ...
	Suffix string

	// The default home chain of a domain name service; e.g. 1 for ENS, 333 for W3NS
	DefaultChainId int
}

// Attributes of a domain name service specific to a chain
type DomainNameServiceChainConfig struct {
	Id DomainNameService

	// The URL to the contract of the resolver
	ResolverAddress common.Address
}


// Web3 protocol error
type Web3ProtocolError struct {
	Type Web3ProtocolErrorType

	// The HTTP code to return to the client
	HttpCode int

	// If the type is RPC failure, this is the HTTP code and message from the RPC
	RpcHttpCode int
	RpcMessage	string

	// If the type is other, this is the error message
	Err string
}

type Web3ProtocolErrorType string // The type of the error
const (
	Web3ProtocolErrorTypeRPCFailure  Web3ProtocolErrorType = "rpcFailure"
	Web3ProtocolErrorTypeOther Web3ProtocolErrorType = "other"
)

func (e *Web3ProtocolError) Error() string {
	if e.Type == Web3ProtocolErrorTypeRPCFailure {
		if e.RpcMessage == "" {
			return fmt.Sprintf("RPC failure with HTTP code %d", e.RpcHttpCode)
		} else {
			return fmt.Sprintf("RPC failure with HTTP code %d and message: %s", e.RpcHttpCode, e.RpcMessage)
		}
	} else {
		return e.Err
	}
}


// An error type with a HTTP code
type ErrorWithHttpCode struct {
	HttpCode int
	Err      string
}

func (e *ErrorWithHttpCode) Error() string {
	return e.Err
}
