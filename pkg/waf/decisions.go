package waf

import (
	wafv2types "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
)

type Decisions struct {
	V4Add        map[string][]*string
	V6Add        map[string][]*string
	V4Del        map[string][]*string
	V6Del        map[string][]*string
	CountriesAdd map[string][]wafv2types.CountryCode
	CountriesDel map[string][]wafv2types.CountryCode
}
