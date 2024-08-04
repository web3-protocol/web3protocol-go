package web3protocol

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
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

// Call a contract with calldata
func (client *Client) callContract(contract common.Address, chain int, calldata []byte) (contractReturn []byte, err error) {
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

	// Create connection
	ethClient, err := ethclient.Dial(client.Config.Chains[chain].RPC)
	if err != nil {
		return contractReturn, &ErrorWithHttpCode{http.StatusBadRequest, err.Error()}
	}
	defer ethClient.Close()

	// Do the contract call
	contractReturn, err = handleCallContract(ethClient, callMessage)
	if err != nil {
		return contractReturn, &ErrorWithHttpCode{http.StatusNotFound, err.Error()}
	}

	return
}

func handleCallContract(client *ethclient.Client, msg ethereum.CallMsg) ([]byte, error) {

	bs, err := client.CallContract(context.Background(), msg, nil)
	if err != nil {
		if err.Error() == "execution reverted" {
			return nil, &ErrorWithHttpCode{http.StatusBadRequest, err.Error()}
		} else {
			return nil, &ErrorWithHttpCode{http.StatusInternalServerError, "internal server error: " + err.Error()}
		}
	}
	return bs, nil
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
