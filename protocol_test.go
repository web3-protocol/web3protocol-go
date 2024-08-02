package web3protocol

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

func TestParseUrl(t *testing.T) {
    client := &Client{
        Config: &Config{
            Chains: map[int]ChainConfig{
                1: {
                    ChainId: 1,
                    ShortName: "eth",
                    RPC: "https://ethereum.publicnode.com/",
                    DomainNameServices: map[DomainNameService]DomainNameServiceChainConfig{},
                },
            },
        },
    }

    url := "web3://0x0000000000000000000000000000000000000000/complexFunction/(bool,uint256,bool,uint256[])!(true,123,false,[456,789])"
    web3Url, err := client.ParseUrl(url)

    if err != nil {
        t.Fatalf("ParseUrl failed: %v", err)
    }
    
    calldata,err := web3Url.ComputeCalldata()
    if err != nil {
        panic(err)
        // t.Fatalf("ComputeCalldata failed: %v", err)
    }
    
    // Pack it with eth abi packer
    
    const abiJSON = `[
        {
            "name": "complexFunction",
            "type": "function",
            "inputs": [
            {
                "name": "complexParam",
                "type": "tuple",
                "components": [
                {
                    "name": "Param1",
                    "type": "bool"
                },
                {
                    "name": "Param2",
                    "type": "uint256"
                },
                {
                    "name": "Param3",
                    "type": "bool"
                },
                {
                    "name": "Param4",
                    "type": "uint256[]"
                }
                ]
            }
            ],
            "outputs": [],
            "stateMutability": "nonpayable"
        }
    ]`
    
    parsedAbi, err := abi.JSON(strings.NewReader(abiJSON))
    if err != nil {
        t.Fatalf("Failed to parse abi: %v", err)
    }
    
    packed, err := parsedAbi.Pack("complexFunction", struct{
        Param1 bool
        Param2 *big.Int
        Param3 bool
        Param4 []*big.Int
    }{
        true, big.NewInt(123), false, []*big.Int{big.NewInt(456), big.NewInt(789)},
    })

    if err != nil {
        t.Fatalf("Failed to pack abi: %v", err)
    }
    
    if hex.EncodeToString(packed) != hex.EncodeToString(calldata) {
        t.Fatalf("Packed data and calldata do not match")
    }

    if web3Url.ResolveMode != ResolveModeAuto {
        t.Errorf("Expected ResolveMode Auto, got %v", web3Url.ResolveMode)
    }
}