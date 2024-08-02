package web3protocol

import (
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

func TestParseArgument(t *testing.T) {
	client := &Client{} // Without ENS support

	tests := []struct {
		name         string
		argument     string
		nsChain      int
		wantAbiType  abi.Type
		wantTypeName string
		wantArgValue interface{}
		wantErr      bool
	}{
		{
			name:         "Parse uint array",
			argument:     "uint64[]![1,3,5]",
			nsChain:      0,
			wantTypeName: "uint64[]",
			wantArgValue: []*big.Int{big.NewInt(1), big.NewInt(3), big.NewInt(5)},
			wantErr:      false,
		},
		{
			name:         "Parse invalid address array",
			argument:     "address[]![1,3,true,false,bytes32!0x111]",
			nsChain:      0,
			wantTypeName: "",
			wantArgValue: nil,
			wantErr:      true,
		},
		{
			name:         "Parse tuple",
			argument:     "(bool,uint256,bool,uint256[])!(true,123,false,[456,789])",
			nsChain:      0,
			wantTypeName: "(bool,uint256,bool,uint256[])",
			wantArgValue: struct{
				A bool
				B *big.Int
				C bool
				D []*big.Int
			}{
				true,
				big.NewInt(123),
				false,
				[]*big.Int{big.NewInt(456), big.NewInt(789)},
			},
			wantErr: false,
		},
		{
			name:         "Parse invalid tuple",
			argument:     "(bool,uint256,string,uint256[])!(true,123,false,[456,abc])",
			nsChain:      0,
			wantTypeName: "",
			wantArgValue: nil,
			wantErr:      true,
		},
		{
			name:         "Parse invalid tuple2",
			argument:     "(bool,uint256,bool,uint256[])!true,123,false,[456,789]",
			nsChain:      0,
			wantTypeName: "",
			wantArgValue: nil,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAbiType, _, gotArgValue, err := client.parseArgument(tt.argument, tt.nsChain)

			if (err != nil) != tt.wantErr {
				t.Errorf("parseArgument() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !deepEqual(gotArgValue, tt.wantArgValue) {
				t.Errorf("parseArgument() gotArgValue = %v, want %v", gotArgValue, tt.wantArgValue)
			}

			if gotAbiType.String() != tt.wantTypeName {
				t.Errorf("parseArgument() gotAbiType = %v, want %v", gotAbiType.String(), tt.wantTypeName)
			}
		})
	}
}

func deepEqual(a, b interface{}) bool {
	// Unwrap interface{} types
	aVal := reflect.ValueOf(a)
	bVal := reflect.ValueOf(b)

	if aVal.Kind() == reflect.Interface || aVal.Kind() == reflect.Ptr {
		aVal = aVal.Elem()
	}
	if bVal.Kind() == reflect.Interface || bVal.Kind() == reflect.Ptr {
		bVal = bVal.Elem()
	}

	// Check if either value is invalid
	if !aVal.IsValid() || !bVal.IsValid() {
		return !aVal.IsValid() && !bVal.IsValid()
	}

	// Handle the case where a and b are slices.
	if aVal.Kind() == reflect.Slice && bVal.Kind() == reflect.Slice {
		if aVal.Len() != bVal.Len() {
			return false
		}
		for i := 0; i < aVal.Len(); i++ {
			if !deepEqual(aVal.Index(i).Interface(), bVal.Index(i).Interface()) {
				return false
			}
		}
		return true
	}

	// Handle the case where a and b are *big.Int.
	if ai, aok := a.(*big.Int); aok {
		if bi, bok := b.(*big.Int); bok {
			return ai.Cmp(bi) == 0
		}
		return false
	}

	// Fallback to reflect.DeepEqual for all other types.
	return fmt.Sprintf("%v", aVal.Interface()) == fmt.Sprintf("%v", bVal.Interface()) || reflect.DeepEqual(a, b)
}
