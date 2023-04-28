package waf

type Decisions struct {
	V4Add        map[string][]*string
	V6Add        map[string][]*string
	V4Del        map[string][]*string
	V6Del        map[string][]*string
	CountriesAdd map[string][]*string
	CountriesDel map[string][]*string
}
