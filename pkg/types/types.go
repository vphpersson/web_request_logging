package types

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type NetworkBase struct {
	RequestId         string             `json:"requestId"`
	Url               string             `json:"url"`
	OriginUrl         string             `json:"originUrl"`
	DocumentUrl       string             `json:"documentUrl"`
	Method            string             `json:"method"`
	Type              string             `json:"type"`
	TimeStamp         int64              `json:"timeStamp"`
	TabId             int                `json:"tabId"`
	FrameId           int                `json:"frameId"`
	ParentFrameId     int                `json:"parentFrameId"`
	Incognito         bool               `json:"incognito"`
	ThirdParty        bool               `json:"thirdParty"`
	CookieStoreId     string             `json:"cookieStoreId"`
	ProxyInfo         *ProxyInfo         `json:"proxyInfo"`
	FrameAncestors    []any              `json:"frameAncestors"`
	UrlClassification *UrlClassification `json:"urlClassification"`
	RequestSize       int                `json:"requestSize"`
	ResponseSize      int                `json:"responseSize"`
}

type NetworkRequest struct {
	NetworkBase
	RequestHeaders []*Header `json:"requestHeaders,omitempty"`
}

type NetworkResponse struct {
	NetworkBase
	IP              string    `json:"ip"`
	StatusCode      int       `json:"statusCode,omitempty"`
	StatusLine      string    `json:"statusLine,omitempty"`
	FromCache       bool      `json:"fromCache,omitempty"`
	ResponseHeaders []*Header `json:"responseHeaders,omitempty"`
}

type ProxyInfo struct {
	// Add fields relevant to proxy info if available
}

type UrlClassification struct {
	FirstParty []string `json:"firstParty"`
	ThirdParty []string `json:"thirdParty"`
}
