package web3protocol

import(
    "strings"
    "mime"
    "net/http"
    "math/big"
    "net/url"
    "regexp"
    "strconv"
    "fmt"
    "errors"

    "github.com/ethereum/go-ethereum/accounts/abi"
    "github.com/ethereum/go-ethereum/common"
)

func (client *Client) parseAutoModeUrl(web3Url *Web3URL, urlMainParts map[string]string) (err error) {
    // Special case : No path, or "/" : we call empty calldata
    if urlMainParts["pathname"] == "" || urlMainParts["pathname"] == "/" {
        web3Url.ContractCallMode = ContractCallModeCalldata
        web3Url.Calldata = []byte{}
        web3Url.ContractReturnProcessing = ContractReturnProcessingDecodeABIEncodedBytes
        return
    }

    pathnameParts := strings.Split(urlMainParts["pathname"], "/")

    // Get method name
    methodName := pathnameParts[1]
    if methodName == "" {
        return &ErrorWithHttpCode{http.StatusBadRequest, "Missing method name"}
    }
    validMethodName, err := regexp.MatchString("^[a-zA-Z$_][a-zA-Z0-9$_]*$", methodName)
    if err != nil {
        return err
    }
    if validMethodName == false {
        return &ErrorWithHttpCode{http.StatusBadRequest, "Invalid method name"}
    }
    web3Url.ContractCallMode = ContractCallModeMethod
    web3Url.MethodName = methodName

    // Resolver for domain name in args : 
    // We use the chain from the initial lookup (erc-6821 allows use to switch chain)
    domainNameResolverChainId := web3Url.ChainId
    if web3Url.HostDomainNameResolverChainId > 0 {
        domainNameResolverChainId = web3Url.HostDomainNameResolverChainId
    }

    for _, pathnamePart := range pathnameParts[2:] {
        abiType, _, value, err := client.parseArgument(pathnamePart, domainNameResolverChainId)
        if err != nil {
            return err
        }
        web3Url.MethodArgs = append(web3Url.MethodArgs, abiType)
        web3Url.MethodArgValues = append(web3Url.MethodArgValues, value)
    }

    // Return processing: By default ABI-encoded bytes
    web3Url.ContractReturnProcessing = ContractReturnProcessingDecodeABIEncodedBytes
    
    // Process the query values
    parsedQuery, err := ParseQuery(urlMainParts["searchParams"])
    if err != nil {
        return &ErrorWithHttpCode{http.StatusBadRequest, "Unable to parse the query of the URL"}
    }
    // Check that we only have the allowed one
    for _, queryValue := range parsedQuery {
        if queryValue.Name != "returns" &&
            queryValue.Name != "returnTypes" &&
            queryValue.Name != "mime.content" &&
            queryValue.Name != "mime.type" {
            return &ErrorWithHttpCode{http.StatusBadRequest, "Unsupported query attribute"}
        }
    }

    // Process the ?returns / ?returnTypes query
    selectedLastQueryParam := parsedQuery.getLastByNames([]string{"returns", "returnTypes"})
    returnTypes := selectedLastQueryParam.Value
    if returnTypes != "" {
        if len(returnTypes) < 2 {
            return &ErrorWithHttpCode{http.StatusBadRequest, "Invalid returns attribute"}
        }
        if string(returnTypes[0]) != "(" || string(returnTypes[len(returnTypes) - 1]) != ")" {
            return &ErrorWithHttpCode{http.StatusBadRequest, "Invalid returns attribute"}
        }

        if returnTypes == "()" {
            // We will return the raw bytes, JSON encoded
            web3Url.ContractReturnProcessing = ContractReturnProcessingRawBytesJsonEncoded
        } else {
            // Ok at this stage we know we are going to return JSON-encoded vars
            web3Url.ContractReturnProcessing = ContractReturnProcessingJsonEncodeValues

            // Remove parenthesis
            returnTypes = returnTypes[1:len(returnTypes) - 1]

            // Do the types parsing
            argMarshalings, err := parseReturnSignature(returnTypes)
            if err != nil {
                return err
            }
            // Convert the abi.ArgumentMarshaling into proper abi.Types
            for _, argMarshaling := range argMarshalings {
                abiType, err := abi.NewType(argMarshaling.Type, "", argMarshaling.Components)
                if err != nil {
                    // We should not enter here, double checking
                    return errors.New("Return attribute processing error: " + argMarshaling.Type);
                }
                web3Url.JsonEncodedValueTypes = append(web3Url.JsonEncodedValueTypes, abiType)
            }            
        }
    }

    // If we are still returning decoded ABI-encoded bytes,
    // Get the mime type to use, from an argument
    if web3Url.ContractReturnProcessing == ContractReturnProcessingDecodeABIEncodedBytes && len(pathnameParts) >= 3 /** At least an argument */ {
        lastPathnamePartParts := strings.Split(pathnameParts[len(pathnameParts) - 1], ".")
        if len(lastPathnamePartParts) > 1 {
            // If no mime type is found, this will return empty string
            web3Url.DecodedABIEncodedBytesMimeType = mime.TypeByExtension("." + lastPathnamePartParts[len(lastPathnamePartParts) - 1])
        }
    }

    // ERC-7087 extension for milme type override
    if web3Url.ContractReturnProcessing == ContractReturnProcessingDecodeABIEncodedBytes {
        selectedLastQueryParam := parsedQuery.getLastByNames([]string{"mime.content", "mime.type"})
        if selectedLastQueryParam.Name == "mime.content" {
            web3Url.DecodedABIEncodedBytesMimeType = selectedLastQueryParam.Value
        } else if selectedLastQueryParam.Name == "mime.type" {
            mimeType := mime.TypeByExtension("." + selectedLastQueryParam.Value)
            // If not found, keep the previous value
            if mimeType != "" {
                web3Url.DecodedABIEncodedBytesMimeType = mimeType
            }
        }
    }

    return
}

// parseArgument parses a [TYPE!]VALUE string into an abi.Type. The type will be auto-detected if TYPE not provided
func (client *Client) parseArgument(argument string, nsChain int) (abiType abi.Type, typeName string, argValue interface{}, err error) {
    // URI-percent-encoding decoding
    var decodedArgument string
    decodedArgument, err = url.PathUnescape(argument)
    if err != nil  {
        err = &ErrorWithHttpCode{http.StatusBadRequest, "Unable to URI-percent decode: " + argument}
        return
    }

    ss := strings.Split(decodedArgument, "!")

    // Type specified
    if len(ss) >= 2 {
        typeName = ss[0]
        argValueStr := strings.Join(ss[1:], "!")

        // If there is a number at the right of the type, extract it
        var typeWithoutSize string
        typeSize := 0
        var typeSizeRegexp *regexp.Regexp
        typeSizeRegexp, err = regexp.Compile(`^([^0-9]+)([1-9][0-9]*)$`)
        if err != nil {
            return
        }
        matches := typeSizeRegexp.FindStringSubmatch(typeName)
        // Type with size
        if matches != nil {
            typeWithoutSize = matches[1]
            typeSize, err = strconv.Atoi(matches[2])
            if err != nil {
                return
            }
        // Type with no size
        } else {
            typeWithoutSize = typeName
        }

        switch typeWithoutSize {
            case "uint", "int":
                // uint/int are aliases of uint256/int256
                if typeSize == 0 {
                    typeSize = 256
                    typeName = fmt.Sprintf("%v%v", typeWithoutSize, typeSize)
                }
                // Type size must be from 8 to 256, by steps of 8
                if typeSize < 8 || typeSize > 256 || typeSize % 8 != 0 {
                    err = &ErrorWithHttpCode{http.StatusBadRequest, "Invalid argument type: " + typeName}
                        return
                }

                b := new(big.Int)
                n, ok := b.SetString(argValueStr, 0)
                if !ok {
                    err = &ErrorWithHttpCode{http.StatusBadRequest, "Argument is not a number: " + argValueStr}
                    return
                }
                if typeWithoutSize == "uint" && n.Cmp(new(big.Int)) == -1 {
                    err = &ErrorWithHttpCode{http.StatusBadRequest, "Number is negative: " + argValueStr}
                    return
                }
                argValue = n

            case "bytes":
                // "bytes", no type size
                if typeSize == 0 {
                    if !has0xPrefix(argValueStr) || !isHex(argValueStr[2:]) {
                        err = &ErrorWithHttpCode{http.StatusBadRequest, "Argument is not a valid hex string: " + argValueStr}
                        return
                    }
                    argValue = common.FromHex(argValueStr)
                // "bytesXX", with a type size
                } else {
                    if typeSize > 32 {
                        err = &ErrorWithHttpCode{http.StatusBadRequest, "Invalid argument type: " + typeName}
                        return
                    }

                    if !has0xPrefix(argValueStr) || !isHex(argValueStr[2:]) {
                        err = &ErrorWithHttpCode{http.StatusBadRequest, "Argument is not a valid hex string: " + argValueStr}
                        return
                    }
                    if len(argValueStr[2:]) != 2 * typeSize {
                        err = &ErrorWithHttpCode{http.StatusBadRequest, "Argument has not the correct length: " + argValueStr}
                        return
                    }
                    argValue = common.HexToHash(argValueStr)
                }

            case "address":
                var addr common.Address
                addr, _, err = client.getAddressFromNameService(nsChain, argValueStr)
                if err != nil {
                    return
                }
                argValue = addr

            case "string":
                argValue = argValueStr

            case "bool":
                if argValueStr != "false" && argValueStr != "true" {
                     err = &ErrorWithHttpCode{http.StatusBadRequest, "Argument must be 'true' or 'false'"}
                        return
                }
                argValue = argValueStr == "true"

            default:
                err = &ErrorWithHttpCode{http.StatusBadRequest, "Unknown type: " + typeName}
                return
        }
        abiType, _ = abi.NewType(typeName, "", nil)

    // No type specified : we autodetect
    } else {
        argValueStr := ss[0]

        // uint256 autodetection
        var numberRegexp *regexp.Regexp
        numberRegexp, _ = regexp.Compile(`^[0-9]+$`)
        matches := numberRegexp.FindStringSubmatch(argValueStr)
        if matches != nil {
            n := new(big.Int)
            n, _ = n.SetString(argValueStr, 10)
            // treat it as uint256
            typeName = "uint256"
            abiType, _ = abi.NewType(typeName, "", nil)
            argValue = n
            return
        }

        // Hex address, bytes32, bytes autodetection
        if has0xPrefix(argValueStr) && isHex(argValueStr[2:]) {
            if len(argValueStr) == 40+2 {
                argValue = common.HexToAddress(argValueStr)
                typeName = "address"
                abiType, _ = abi.NewType(typeName, "", nil)
                return
            } else if len(argValueStr) == 64+2 {
                argValue = common.HexToHash(argValueStr)
                typeName = "bytes32"
                abiType, _ = abi.NewType(typeName, "", nil)
                return
            } else {
                argValue = common.FromHex(argValueStr[2:])
                typeName = "bytes"
                abiType, _ = abi.NewType(typeName, "", nil)
                return
            }
        }

        // Bool autodetection
        if argValueStr == "true" || argValueStr == "false" {
            argValue = argValueStr == "true"
            typeName = "bool"
            abiType, _ = abi.NewType(typeName, "", nil)
            return
        }

        // Domain name address autodetection
        var addr common.Address
        addr, _, err = client.getAddressFromNameService(nsChain, argValueStr)
        if err == nil {
            argValue = addr
            typeName = "address"
            abiType, _ = abi.NewType(typeName, "", nil)
            return abiType, "address", addr, nil
        }
    }

    return
}

// Recursively parse the ?returns= signature
// It follows the syntax of the argument part of the ABI method signature
func parseReturnSignature(text string) (result []abi.ArgumentMarshaling, err error) {
    // Separate parts
    parts := []string{}
    if len(text) > 0 {
        tupleDeepness := 0
        lastCommaPos := -1
        for i, char := range text {
            if char == []rune("(")[0] {
                tupleDeepness++
            } else if char == []rune(")")[0] {
                tupleDeepness--
            } else if char == []rune(",")[0] && tupleDeepness == 0 {
                parts = append(parts, string([]rune(text)[lastCommaPos + 1:i]))
                lastCommaPos = i
            }
        }
        parts = append(parts, string([]rune(text)[lastCommaPos + 1:]))
    }

    // Process parts
    for _, part := range parts {
        // Look for tuple
        tupleRegexp, _ := regexp.Compile(`^\((?P<tupleComponents>.+)\)(?P<arrayDef>[\[\]0-9]*)$`)
        tupleMatches := tupleRegexp.FindStringSubmatch(part)
        if len(tupleMatches) > 0 {
            tupleComponents, err := parseReturnSignature(tupleMatches[1])
            if err != nil {
                return result, err
            }
            result = append(result, abi.ArgumentMarshaling{Type: "tuple" + tupleMatches[2], Name: "x", Components: tupleComponents})
        // Basic type
        } else {
            if part == "" {
                return result, &ErrorWithHttpCode{http.StatusBadRequest, "Return attribute: missing type"}
            }

            // Aliases uint and int are allowed
            if part == "uint" {
                part = "uint256"
            } else if part == "int" {
                part = "int256"
            }

            _, err := abi.NewType(part, "", nil)
            if err != nil {
                return result, &ErrorWithHttpCode{http.StatusBadRequest, "Return attribute: Invalid type: " + part}
            }
            result = append(result, abi.ArgumentMarshaling{Type: part, Name: "x"})
        }
    }

    return
}