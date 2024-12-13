package web3protocol

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	goEthereumRpc "github.com/ethereum/go-ethereum/rpc"
	// log "github.com/sirupsen/logrus"
)

// has0xPrefix validates str begins with '0x' or '0X'.
func has0xPrefix(str string) bool {
	return len(str) >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')
}

// isHexCharacter returns bool of c being a valid hexadecimal.
func isHexCharacter(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

// isHex validates whether each byte is valid hexadecimal string.
func isHex(str string) bool {
	if len(str)%2 != 0 {
		return false
	}
	for _, c := range []byte(str) {
		if !isHexCharacter(c) {
			return false
		}
	}
	return true
}

// Used for auto mode returning JSON :
// For a given ABI type and a value, convert it to a string, with the data formatted
// according to the spec
func JsonEncodeAbiTypeValue(arg abi.Type, value interface{}) (result interface{}, err error) {
	switch arg.T {
	case abi.StringTy:
		result = value

	case abi.BoolTy:
		result = value

	case abi.IntTy, abi.UintTy:
		result = fmt.Sprintf("0x%x", value)

	case abi.FixedPointTy, abi.AddressTy:
		result = fmt.Sprintf("%v", value)

	case abi.BytesTy, abi.FixedBytesTy, abi.HashTy:
		result = fmt.Sprintf("0x%x", value)

	case abi.SliceTy, abi.ArrayTy:
		ty := *arg.Elem
		result = make([]interface{}, 0)
		rv := reflect.ValueOf(value)
		for i := 0; i < rv.Len(); i++ {
			subResult, err := JsonEncodeAbiTypeValue(ty, rv.Index(i).Interface())
			if err != nil {
				return result, err
			}
			result = append(result.([]interface{}), subResult)
		}

	case abi.TupleTy:
		result = make([]interface{}, 0)
		rv := reflect.ValueOf(value)
		for i := 0; i < rv.NumField(); i++ {
			subResult, err := JsonEncodeAbiTypeValue(*arg.TupleElems[i], rv.Field(i).Interface())
			if err != nil {
				return result, err
			}
			result = append(result.([]interface{}), subResult)
		}

	default:
		err = errors.New(fmt.Sprintf("Unsupported type: 0x%x", arg.T))
	}

	return
}

// For a method signature and the actual arguments, generate the calldata
func methodCallToCalldata(methodName string, methodArgTypes []abi.Type, methodArgValues []interface{}) (calldata []byte, err error) {
	// ABI-encode the arguments
	abiArguments := abi.Arguments{}
	for _, methodArgType := range methodArgTypes {
		abiArguments = append(abiArguments, abi.Argument{Type: methodArgType})
	}
	calldataArgumentsPart, err := abiArguments.Pack(methodArgValues...)
	if err != nil {
		return
	}

	// Determine method signature
	methodSignature := methodName + "("
	for i, methodArgType := range methodArgTypes {
		methodSignature += methodArgType.String()
		if i < len(methodArgTypes)-1 {
			methodSignature += ","
		}
	}
	methodSignature += ")"
	methodSignatureHash := crypto.Keccak256Hash([]byte(methodSignature))

	// Compute the calldata
	calldata = append(methodSignatureHash[0:4], calldataArgumentsPart...)

	return
}

// Find an available RPC for the chain. If no available RPC, find one in tooManyRequests state. If
// none are available, return an error.
func (client *Client) findAvailableRpc(chain int, allowTooManyRequestsRPCs bool) (rpc *Rpc, err error) {
	client.RpcsMutex.RLock()
	defer client.RpcsMutex.RUnlock()

	rpcs, ok := client.Rpcs[chain]
	if !ok {
		err = errors.New(fmt.Sprintf("No RPCs found for chain %d", chain))
		return
	}

	for _, rpc = range rpcs {
		if rpc.State == RpcStateAvailable {
			return
		}
	}

	if allowTooManyRequestsRPCs {
		for _, rpc = range rpcs {
			if rpc.State == RpcStateTooManyRequests {
				return
			}
		}
	}

	err = errors.New(fmt.Sprintf("No available RPCs found for chain %d", chain))
	return
}

// Get the RPC to be used by system workers (e.g. ERC-7774), by chain
func (client *Client) GetSystemRpcUrl(chain int) (rpcUrl string, err error) {
	chainConfig, ok := client.Config.Chains[chain]
	if !ok {
		err = errors.New(fmt.Sprintf("No chain found for chain %d", chain))
		return
	}
	rpcUrl = chainConfig.SystemRPC
	if rpcUrl == "" {
		rpc, err := client.findAvailableRpc(chain, true)
		if err != nil {
			return rpcUrl, err
		}
		rpcUrl = rpc.Config.Url
	}

	return
}


// Call a contract with calldata
func (client *Client) callContract(contract common.Address, chain int, calldata []byte) (contractReturn []byte, err error) {
	// Find an available RPC for the chain. If no available RPC, find one in tooManyRequests state. If
	// none are available, return an error.
	rpc, err := client.findAvailableRpc(chain, true)
	if err != nil {
		return contractReturn, &ErrorWithHttpCode{http.StatusServiceUnavailable, err.Error()}
	}

	// Create connection
	ethClient, err := ethclient.Dial(rpc.Config.Url)
	if err != nil {
		return contractReturn, &ErrorWithHttpCode{http.StatusBadRequest, err.Error()}
	}
	defer ethClient.Close()

	// Prepare the ethereum message to send
	callMessage := ethereum.CallMsg{
		From:      common.HexToAddress("0x0000000000000000000000000000000000000000"),
		To:        &contract,
		Gas:       0,
		GasPrice:  nil,
		GasFeeCap: nil,
		GasTipCap: nil,
		Data:      calldata,
		Value:     nil,
	}


	//
	// Loop: For a given time, we try to call the contract.
	// As long as the RPC is 429, we wait for it to be available
	// until the maxRpcWaitedDuration is reached
	//

	// Wait for one request slot to be available
	rpc.RequestSemaphone <- struct{}{}
	defer func() {<-rpc.RequestSemaphone}()

	// How long did we wait for the RPC to be available
	rpcWaitedDuration := 0 * time.Second
	// How often do we check if the RPC is available
	rpcWaitInterval := 1 * time.Second
	// The maximum time we wait for the RPC to be available
	maxRpcWaitedDuration := 30 * time.Second

	for notExecuted := true; notExecuted; notExecuted = (err != nil) {

		//
		// If the RPC is not available, wait for it to be available
		//

		// If the RPC is right now not available, wait for it to be available
		// Basic polling loop, no channels yet
		client.RpcsMutex.RLock()
		rpcState := rpc.State
		client.RpcsMutex.RUnlock()
		for rpcState != RpcStateAvailable {
			// 429 State
			if rpcState == RpcStateTooManyRequests {
				// Wait for the RPC to be available
				rpcWaitedDuration += rpcWaitInterval
				if rpcWaitedDuration > maxRpcWaitedDuration {
					return contractReturn, &ErrorWithHttpCode{http.StatusServiceUnavailable, "RPC has been in 429 Too Many Requests state for too long"}
				}
				time.Sleep(rpcWaitInterval)

				// Check if the RPC is available
				client.RpcsMutex.RLock()
				rpcState = rpc.State
				client.RpcsMutex.RUnlock()
			// 401 State (Would be weird to switch from 429 to 401, but anyway let's check)
			} else if rpcState == RpcStateUnauthorized {
				return contractReturn, &ErrorWithHttpCode{http.StatusUnauthorized, "RPC is unauthorized"}
			}
		}

		//
		// Do the contract call
		//

		// Do the call
		contractReturn, err = ethClient.CallContract(context.Background(), callMessage, nil)


		//
		// Handle errors of the call execution
		//

		if err != nil {
			// fmt.Printf("callContract Error %+v\n", err)
			// fmt.Printf("callContract Error type: %T\n", err)

			// If error is not of type rpc.HTTPError, we return with an error
			if _, ok := err.(goEthereumRpc.HTTPError); !ok {
				return contractReturn, &ErrorWithHttpCode{http.StatusInternalServerError, err.Error()}
			}

			// Get the RPC error
			rpcErr := err.(goEthereumRpc.HTTPError)

			// If the error is a 401 Unauthorized, switch the RPC to unauthorized
			if rpcErr.StatusCode == http.StatusUnauthorized {
				client.RpcsMutex.Lock()
				rpc.State = RpcStateUnauthorized
				client.RpcsMutex.Unlock()
				return contractReturn, &ErrorWithHttpCode{http.StatusInternalServerError, "RPC is unauthorized"}
			}
			// IF the RPC is not 429, return with an error
			if rpcErr.StatusCode != http.StatusTooManyRequests {
				return contractReturn, &ErrorWithHttpCode{http.StatusInternalServerError, err.Error()}
			}

			// If the RPC is 429, switch the RPC to tooManyRequests, and we restart the loop,
			// waiting for the RPC to be available
			client.RpcsMutex.Lock()
			if rpc.State != RpcStateTooManyRequests {
				rpc.State = RpcStateTooManyRequests
				// Start a goroutine to check if the RPC is available again
				go client.CheckTooManyRequestsStateWorker(rpc)
			}
			client.RpcsMutex.Unlock()
		}
	}


	return
}


// URL.parseQuery does not preserve the order of query attributes
// This is a version which keep order
type QueryParameter struct {
	Name  string
	Value string
}
type QueryParameters []QueryParameter

func ParseQuery(query string) (params QueryParameters, err error) {
	params = []QueryParameter{}

	for query != "" {
		var key string
		key, query, _ = strings.Cut(query, "&")
		if strings.Contains(key, ";") {
			err = fmt.Errorf("invalid semicolon separator in query")
			continue
		}
		if key == "" {
			continue
		}
		key, value, _ := strings.Cut(key, "=")
		key, err1 := url.QueryUnescape(key)
		if err1 != nil {
			if err == nil {
				err = err1
			}
			continue
		}
		value, err1 = url.QueryUnescape(value)
		if err1 != nil {
			if err == nil {
				err = err1
			}
			continue
		}
		params = append(params, QueryParameter{
			Name:  key,
			Value: value,
		})
	}

	return
}

func (params *QueryParameters) getLastByNames(names []string) (value QueryParameter) {
	for i := len(*params) - 1; i >= 0; i-- {
		for _, name := range names {
			if (*params)[i].Name == name {
				value = (*params)[i]
				return
			}
		}
	}

	return
}
