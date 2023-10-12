package web3protocol

import (
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
func (config *Config) getChainIdByShortName(shortName string) (result int) {
    for chainId, _ := range config.Chains {
        if config.Chains[chainId].ShortName == shortName {
            result = chainId
            break
        }
    }

    return
}
func (config *Config) getDomainNameServiceBySuffix(suffix string) (result DomainNameService) {
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


// An error type with a HTTP code
type Web3Error struct {
    HttpCode int
    err  string
}
func (e *Web3Error) Error() string {
    return e.err
}