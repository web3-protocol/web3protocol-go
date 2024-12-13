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
	RPC ChainRPCConfig

	// System RPC : RPC used by system workers (right now, ERC-7774 and its event caching checks)
	// It will not be used for user requests, and has to be different from the main RPCs
	// Aim : If the main RPCs are down, the system workers can still work
	// If empty, the default RPC is used
	SystemRPC string

	// A chain-specific config per domain name service. Key is their short name.
	DomainNameServices map[DomainNameService]DomainNameServiceChainConfig
}

type ChainRPCConfig struct {
	// The RPC URL to use to call the chain
	Url string
	// The maximum number of parralel requests to the RPC
	MaxConcurrentRequests int
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

// Go-Ethereum use an internal jsonError type; to be able to read it we redeclare it here
type JsonError interface {
	Error() string
	ErrorCode() int
	ErrorData() interface{}
}


// Web3 protocol error
type Web3ProtocolError struct {
	Type Web3ProtocolErrorType

	// The HTTP code to return to the client
	HttpCode int

	// If the type is RPC error, this is the HTTP code and message from the RPC
	RpcHttpCode int

	// If the type is RPC JSON error, this is the JSON error from the RPC
	JsonErrorCode int
	JsonErrorData interface{}

	// The original error, if any
	Err error
}

type Web3ProtocolErrorType string // The type of the error
const (
	// The RPC call itself failed (bad HTTP code)
	Web3ProtocolErrorTypeRPCError  Web3ProtocolErrorType = "rpcError"
	// The RPC call succeeded, but the JSON returned by the RPC is an error
	Web3ProtocolErrorTypeRPCJsonError Web3ProtocolErrorType = "rpcJsonError"
	// Other
	Web3ProtocolErrorTypeOther Web3ProtocolErrorType = ""
)

func (e *Web3ProtocolError) Error() string {
	if e.Type == Web3ProtocolErrorTypeRPCError {
			return fmt.Sprintf("RPC call error with HTTP code %d : %s", e.RpcHttpCode, e.Err)
	} else if e.Type == Web3ProtocolErrorTypeRPCJsonError {
		return fmt.Sprintf("RPC call error with JSON error code %d : %s", e.JsonErrorCode, e.Err)
	} else {
		return e.Err.Error()
	}
}

