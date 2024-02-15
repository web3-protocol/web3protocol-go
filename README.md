# web3protocol-go

Parse and execute [ERC-6860 / ERC-4804 ``web3://`` protocol](https://eips.ethereum.org/EIPS/eip-6860) URLs.

## Usage

```
import "github.com/web3-protocol/web3protocol-go"

config := web3protocol.Config{ ... } // Fill with the example in the configuration section
client := NewClient(&config)

fetchedWeb3Url, err := client.FetchUrl("web3://terraformnavigator.eth/view/1234")

fmt.Println("HTTP return code:", fetchedWeb3Url.HttpCode)
fmt.Printf("HTTP return headers: %+v\n", fetchedWeb3Url.HttpHeaders)

output, err := ioutil.ReadAll(fetchedWeb3Url.Output)
fmt.Println("Output bytes", output)
```

On top of the result, ``fetchedWeb3Url`` contains a lot more details on the processing of the call.

## Configuration

Right now, by default, this does not come with chains and domain name definitions; they will need to be provided. Here is an example for a basic Ethereum mainnet + ENS config, using the publicnode.com RPCs : 

```
config := Config {
    Chains: map[int]ChainConfig{
        1: ChainConfig{
            ChainId: 1,
            ShortName: "eth",
            RPC: "https://ethereum.publicnode.com/",
            DomainNameServices: map[DomainNameService]DomainNameServiceChainConfig{
                DomainNameServiceENS: DomainNameServiceChainConfig{
                    Id: DomainNameServiceENS,
                    ResolverAddress: common.HexToAddress("0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"),
                },
            },
        },
    },
    DomainNameServices: map[DomainNameService]DomainNameServiceConfig{
        DomainNameServiceENS: DomainNameServiceConfig{
            Id: DomainNameServiceENS,
            Suffix: "eth",
            DefaultChainId: 1,
        },
    },
}
```

## Supported standards

### Implemented features

- [ERC-6860](https://eips.ethereum.org/EIPS/eip-6860) (draft) : the base web3:// protocol with auto and manual mode, basic ENS support. This updates [ERC-4804](https://eips.ethereum.org/EIPS/eip-4804) (final) with clarifications, small fixes and changes.
- [ERC-6821](https://eips.ethereum.org/EIPS/eip-6821) (draft) : ENS resolution : support for the ``contentcontract`` TXT field to point to a contract in another chain
- [ERC-6944](https://eips.ethereum.org/EIPS/eip-6944) (draft) / [ERC-5219](https://eips.ethereum.org/EIPS/eip-5219) (final) : New mode offloading some parsing processing on the browser side
- [ERC-7617](https://github.com/ethereum/ERCs/pull/245) (pending): Add chunk support in ERC-6944 resource request mode
- [ERC-7618](https://github.com/ethereum/ERCs/pull/246) (pending): Add Content-encoding handling in ERC-6944 resource request mode

### Partially implemented features

- [ERC-7087](https://eips.ethereum.org/EIPS/eip-7087) (draft) :  Auto mode : Add MIME type support (dataURLs not supported yet)

## Testing

Web3:// test files are located in [their own git repository](https://github.com/web3-protocol/web3protocol-tests) and are imported as a git submodule. After cloning, please run ``git submodule init`` and then ``git submodule update``.

Testing is then launched with ``go test``
