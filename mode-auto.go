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

    "github.com/ethereum/go-ethereum/accounts/abi"
    "github.com/ethereum/go-ethereum/common"
)

func (client *Client) parseAutoModeUrl(web3Url *Web3URL, urlMainParts map[string]string) (err error) {
    // Special case : No path : we call empty calldata
    if urlMainParts["pathname"] == "" {
        web3Url.ContractCallMode = ContractCallModeCalldata
        web3Url.Calldata = []byte{}
        web3Url.ContractReturnProcessing = ContractReturnProcessingABIEncodedBytes
        return
    }

    pathnameParts := strings.Split(urlMainParts["pathname"], "/")

    // Get method name
    methodName := pathnameParts[1]
    if methodName == "" {
        return &Web3Error{http.StatusBadRequest, "Missing method name"}
    }
    validMethodName, err := regexp.MatchString("^[a-zA-Z$_][a-zA-Z0-9$_]*$", methodName)
    if err != nil {
        return err
    }
    if validMethodName == false {
        return &Web3Error{http.StatusBadRequest, "Invalid method name"}
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
    web3Url.ContractReturnProcessing = ContractReturnProcessingABIEncodedBytes
    
    // Process the ?returns / ?returnTypes query
    parsedQuery, err := url.ParseQuery(urlMainParts["searchParams"])
    if err != nil {
        return err
    }
    returnTypesValue := parsedQuery["returnTypes"]
    returnsValue := parsedQuery["returns"]
    if len(returnsValue) > 0 && len(returnTypesValue) > 0 || len(returnsValue) >= 2 || len(returnTypesValue) >= 2 {
        return &Web3Error{http.StatusBadRequest, "Duplicate return attribute"}
    }
    var rType string
    if len(returnsValue) == 1 {
        rType = returnsValue[0]
    } else if len(returnTypesValue) == 1 {
        rType = returnTypesValue[0]
    }

    if rType != "" {
        if len(rType) < 2 {
            return &Web3Error{http.StatusBadRequest, "Invalid returns attribute"}
        }
        if string(rType[0]) != "(" || string(rType[len(rType) - 1]) != ")" {
            return &Web3Error{http.StatusBadRequest, "Invalid returns attribute"}
        }

        if rType == "()" {
            // We will return the raw bytes, JSON encoded
            web3Url.ContractReturnProcessing = ContractReturnProcessingRawBytesJsonEncoded
        } else {
            // Ok at this stage we know we are going to return JSON-encoded vars
            web3Url.ContractReturnProcessing = ContractReturnProcessingJsonEncodeValues

            // Remove parenthesis
            rType = rType[1:len(rType) - 1]

            // Do the types parsing
            rTypeParts := strings.Split(rType, ",")
            web3Url.JsonEncodedValueTypes = []abi.Type{}
            for _, rTypePart := range rTypeParts {
                abiType, err := abi.NewType(rTypePart, "", nil)
                if err != nil {
                    return &Web3Error{http.StatusBadRequest, "Invalid type: " + rTypePart}
                }
                web3Url.JsonEncodedValueTypes = append(web3Url.JsonEncodedValueTypes, abiType)
            }
        }
    }

    // If we are still returning decoded ABI-encoded bytes,
    // Get the mime type to use, from an argument
    if web3Url.ContractReturnProcessing == ContractReturnProcessingABIEncodedBytes && len(pathnameParts) >= 3 /** At least an argument */ {
        lastPathnamePartParts := strings.Split(pathnameParts[len(pathnameParts) - 1], ".")
        if len(lastPathnamePartParts) > 1 {
            // If no mime type is found, this will return empty string
            web3Url.DecodedABIEncodedBytesMimeType = mime.TypeByExtension("." + lastPathnamePartParts[len(lastPathnamePartParts) - 1])
        }
    }

    return
}






// parseArgument parses a [TYPE!]VALUE string into an abi.Type. The type will be auto-detected if TYPE not provided
func (client *Client) parseArgument(argument string, nsChain int) (abiType abi.Type, typeName string, argValue interface{}, err error) {
    ss := strings.Split(argument, "!")
    if len(ss) > 2 {
        err = &Web3Error{http.StatusBadRequest, "Argument wrong format: " + argument}
        return
    }

    if len(ss) == 2 {
        typeName = ss[0]
        argValueStr := ss[1]

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
                    err = &Web3Error{http.StatusBadRequest, "Invalid argument type: " + typeName}
                        return
                }

                b := new(big.Int)
                n, ok := b.SetString(argValueStr, 0)
                if !ok {
                    err = &Web3Error{http.StatusBadRequest, "Argument is not a number: " + argValueStr}
                    return
                }
                if typeWithoutSize == "uint" && n.Cmp(new(big.Int)) == -1 {
                    err = &Web3Error{http.StatusBadRequest, "Number is negative: " + argValueStr}
                    return
                }
                argValue = n

            case "bytes":
                // "bytes", no type size
                if typeSize == 0 {
                    if !has0xPrefix(argValueStr) || !isHex(argValueStr[2:]) {
                        err = &Web3Error{http.StatusBadRequest, "Argument is not a valid hex string: " + argValueStr}
                        return
                    }
                    argValue = common.FromHex(argValueStr)
                // "bytesXX", with a type size
                } else {
                    if typeSize > 32 {
                        err = &Web3Error{http.StatusBadRequest, "Invalid argument type: " + typeName}
                        return
                    }

                    if !has0xPrefix(argValueStr) || !isHex(argValueStr[2:]) {
                        err = &Web3Error{http.StatusBadRequest, "Argument is not a valid hex string: " + argValueStr}
                        return
                    }
                    if len(argValueStr[2:]) != 2 * typeSize {
                        err = &Web3Error{http.StatusBadRequest, "Argument has not the correct length: " + argValueStr}
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
                // URI-percent-encoding decoding
                var decodedArgValue string
                decodedArgValue, err = url.PathUnescape(argValueStr)
                if err != nil  {
                    err = &Web3Error{http.StatusBadRequest, "Unable to URI-percent decode: " + argValueStr}
                    return
                }
                argValue = decodedArgValue

            case "bool":
                if argValueStr != "false" && argValueStr != "true" {
                     err = &Web3Error{http.StatusBadRequest, "Argument must be 'true' or 'false'"}
                        return
                }
                argValue = argValueStr == "true"

            default:
                err = &Web3Error{http.StatusBadRequest, "Unknown type: " + typeName}
                return
        }
        abiType, _ = abi.NewType(typeName, "", nil)

    // No type specified : we autodetect
    } else {
        argValueStr := ss[0]

        n := new(big.Int)
        n, success := n.SetString(argValueStr, 10)
        if success {
            // Check that positive
            if n.Cmp(new(big.Int)) == -1 {
                err = &Web3Error{http.StatusBadRequest, "Number is negative: " + argValueStr}
                return
            }
            // treat it as uint256
            typeName = "uint256"
            abiType, _ = abi.NewType(typeName, "", nil)
            argValue = n
            return
        }

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

        // parse as domain name
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

