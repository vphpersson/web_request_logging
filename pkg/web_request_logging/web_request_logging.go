package web_request_logging

import (
	"fmt"
	"github.com/Motmedel/ecs_go/ecs"
	"github.com/Motmedel/utils_go/pkg/net/domain_breakdown"
	networkLoggingTypes "github.com/vphpersson/web_request_logging/pkg/types"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var httpVersionPattern = regexp.MustCompile(`^HTTP/([^ ]+) \d+(\s+(.*))?$`)

func EnrichWithNetworkBase(
	base *networkLoggingTypes.EcsWebRequestLoggingBase,
	networkBase *networkLoggingTypes.NetworkBase,
) {
	if base == nil {
		return
	}

	if networkBase == nil {
		return
	}

	ecsNetwork := base.Network
	if ecsNetwork == nil {
		ecsNetwork = &ecs.Network{}
		base.Network = ecsNetwork
	}
	ecsNetwork.Application = "firefox"
	ecsNetwork.Protocol = "http"

	ecsHttp := base.Http
	if ecsHttp == nil {
		ecsHttp = &ecs.Http{}
		base.Http = ecsHttp
	}
	ecsHttpRequest := ecsHttp.Request
	if ecsHttpRequest == nil {
		ecsHttpRequest = &ecs.HttpRequest{}
		ecsHttp.Request = ecsHttpRequest
	}
	ecsHttpRequest.Id = networkBase.RequestId
	ecsHttpRequest.Method = networkBase.Method
	ecsHttpRequest.Referrer = networkBase.OriginUrl

	ecsWebRequestLogging := base.WebRequestLogging
	if ecsWebRequestLogging == nil {
		ecsWebRequestLogging = &networkLoggingTypes.EcsWebRequestLogging{}
		base.WebRequestLogging = ecsWebRequestLogging
	}
	ecsWebRequestLogging.TabId = networkBase.TabId
	ecsWebRequestLogging.Type = networkBase.Type

	parsedUrl, _ := url.Parse(networkBase.Url)
	if parsedUrl == nil {
		return
	}

	hostname := parsedUrl.Hostname()

	var username string
	var password string
	if userInfo := parsedUrl.User; userInfo != nil {
		username = userInfo.Username()
		password, _ = userInfo.Password()
	}

	ecsUrl := base.Url
	if ecsUrl == nil {
		ecsUrl = &ecs.Url{}
		base.Url = ecsUrl
	}

	ecsUrl.Domain = hostname
	ecsUrl.Extension = strings.TrimPrefix(filepath.Ext(parsedUrl.Path), ".")
	ecsUrl.Fragment = parsedUrl.Fragment
	ecsUrl.Original = networkBase.Url
	ecsUrl.Full = networkBase.Url
	ecsUrl.Password = password
	ecsUrl.Path = parsedUrl.Path
	ecsUrl.Query = parsedUrl.RawQuery
	ecsUrl.Scheme = parsedUrl.Scheme
	ecsUrl.Username = username

	var port int
	if parsedUrlPort := parsedUrl.Port(); parsedUrlPort != "" {
		var err error
		port, err = strconv.Atoi(parsedUrlPort)
		if err != nil {
			ecsUrl.Port = port
		}
	} else {
		switch parsedUrl.Scheme {
		case "http":
			port = 80
		case "https":
			port = 443
		}
	}

	ecsServer := base.Server
	if ecsServer == nil {
		ecsServer = &ecs.Target{}
		base.Server = ecsServer
	}
	ecsServer.Address = hostname
	ecsServer.Port = port

	requestUrlBreakdown := domain_breakdown.GetDomainBreakdown(hostname)
	if requestUrlBreakdown != nil {
		ecsUrl.RegisteredDomain = requestUrlBreakdown.RegisteredDomain
		ecsServer.RegisteredDomain = requestUrlBreakdown.RegisteredDomain

		ecsUrl.Subdomain = requestUrlBreakdown.Subdomain
		ecsServer.Subdomain = requestUrlBreakdown.Subdomain

		ecsUrl.TopLevelDomain = requestUrlBreakdown.TopLevelDomain
		ecsServer.TopLevelDomain = requestUrlBreakdown.TopLevelDomain

		ecsServer.Domain = hostname
	} else {
		if parsedIp := net.ParseIP(hostname); parsedIp != nil {
			ecsServer.Ip = parsedIp.String()
		}
	}
}

func EnrichWithNetworkRequest(
	base *networkLoggingTypes.EcsWebRequestLoggingBase,
	networkRequest *networkLoggingTypes.NetworkRequest,
) {
	if base == nil {
		return
	}

	if networkRequest == nil {
		return
	}

	parsedTimestamp := time.UnixMilli(networkRequest.TimeStamp).UTC().Format("2006-01-02T15:04:05.999Z")
	base.Timestamp = parsedTimestamp

	ecsEvent := base.Event
	if ecsEvent == nil {
		ecsEvent = &ecs.Event{}
		base.Event = ecsEvent
	}
	base.Event.Start = parsedTimestamp

	ecsHttp := base.Http
	if ecsHttp == nil {
		ecsHttp = &ecs.Http{}
		base.Http = ecsHttp
	}
	ecsHttpRequest := ecsHttp.Request
	if ecsHttpRequest == nil {
		ecsHttpRequest = &ecs.HttpRequest{}
		ecsHttp.Request = ecsHttpRequest
	}

	var headerStrings []string
	for _, header := range networkRequest.RequestHeaders {
		headerName := header.Name
		headerValue := header.Value

		switch strings.ToLower(headerName) {
		case "content-type":
			ecsHttpRequest.ContentType = headerValue
		case "set-cookie":
			fallthrough
		case "cookie":
			fallthrough
		case "authorization":
			// Mask potentially sensitive value.
			headerValue = "(MASKED)"
		}

		headerStrings = append(headerStrings, fmt.Sprintf("%s: %s\r\n", headerName, headerValue))
	}
	if len(headerStrings) != 0 {
		ecsHttpRequest.HttpHeaders = &ecs.HttpHeaders{
			Normalized: strings.Join(headerStrings, ""),
		}
	}

	EnrichWithNetworkBase(base, &networkRequest.NetworkBase)
}

func EnrichWithNetworkResponse(
	base *networkLoggingTypes.EcsWebRequestLoggingBase,
	networkResponse *networkLoggingTypes.NetworkResponse,
) {
	if base == nil {
		return
	}

	if networkResponse == nil {
		return
	}

	parsedTimestamp := time.UnixMilli(networkResponse.TimeStamp).UTC().Format("2006-01-02T15:04:05.999Z")
	base.Timestamp = parsedTimestamp

	ecsEvent := base.Event
	if ecsEvent == nil {
		ecsEvent = &ecs.Event{}
		base.Event = ecsEvent
	}
	ecsEvent.End = parsedTimestamp

	ecsServer := base.Server
	if ecsServer == nil {
		ecsServer = &ecs.Target{}
		base.Server = ecsServer
	}
	if networkResponseIp := net.ParseIP(networkResponse.Ip); networkResponseIp != nil {
		ecsServer.Ip = networkResponseIp.String()
	}

	ecsHttp := base.Http
	if ecsHttp == nil {
		ecsHttp = &ecs.Http{}
		base.Http = ecsHttp
	}

	var httpVersion string
	var reasonPhrase string
	if matches := httpVersionPattern.FindStringSubmatch(networkResponse.StatusLine); matches != nil && len(matches) > 1 {
		httpVersion = matches[1]
		reasonPhrase = matches[3]
	}

	if httpVersion != "" {
		ecsHttp.Version = httpVersion

		ecsNetwork := base.Network
		if ecsNetwork == nil {
			ecsNetwork = &ecs.Network{}
			base.Network = ecsNetwork
		}
		if strings.HasPrefix(httpVersion, "3.") {
			ecsNetwork.Transport = "udp"
			ecsNetwork.IanaNumber = "17"
		} else {
			ecsNetwork.Transport = "tcp"
			ecsNetwork.IanaNumber = "6"
		}
	}

	ecsHttpResponse := ecsHttp.Response
	if ecsHttpResponse != nil {
		ecsHttpResponse = &ecs.HttpResponse{}
		ecsHttp.Response = ecsHttpResponse
	}
	ecsHttpResponse.StatusCode = networkResponse.StatusCode
	ecsHttpResponse.ReasonPhrase = reasonPhrase

	var headerStrings []string
	for _, header := range networkResponse.ResponseHeaders {
		headerName := header.Name
		headerValue := header.Value

		switch strings.ToLower(headerName) {
		case "content-type":
			ecsHttpResponse.ContentType = headerValue
		case "set-cookie":
			fallthrough
		case "cookie":
			fallthrough
		case "authorization":
			// Mask potentially sensitive value.
			headerValue = "(MASKED)"
		}

		headerStrings = append(headerStrings, fmt.Sprintf("%s: %s\r\n", headerName, headerValue))
	}
	if len(headerStrings) != 0 {
		ecsHttpResponse.HttpHeaders = &ecs.HttpHeaders{
			Normalized: strings.Join(headerStrings, ""),
		}
	}

	ecsWebRequestLogging := base.WebRequestLogging
	if ecsWebRequestLogging == nil {
		ecsWebRequestLogging = &networkLoggingTypes.EcsWebRequestLogging{}
		base.WebRequestLogging = ecsWebRequestLogging
	}
	ecsWebRequestLogging.FromCache = &networkResponse.FromCache
}
