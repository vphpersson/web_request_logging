package web_request_logging

import (
	"encoding/json"
	"fmt"
	"github.com/Motmedel/ecs_go/ecs"
	"github.com/Motmedel/utils_go/pkg/net/domain_breakdown"
	networkLoggingErrors "github.com/vphpersson/web_request_logging/pkg/errors"
	networkLoggingTypes "github.com/vphpersson/web_request_logging/pkg/types"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var httpVersionPattern = regexp.MustCompile(`^HTTP/([^ ]+) \d+( (.+))?$`)

func ParseNetworkBase(details *networkLoggingTypes.NetworkBase) (*ecs.Base, error) {
	if details == nil {
		return nil, nil
	}

	parsedUrl, err := url.Parse(details.Url)
	if err != nil {
		return nil, fmt.Errorf("failed to parse url: %w", err)
	}

	hostname := parsedUrl.Hostname()

	var username string
	var password string
	if userInfo := parsedUrl.User; userInfo != nil {
		username = userInfo.Username()
		password, _ = userInfo.Password()
	}

	ecsUrl := &ecs.Url{
		Domain:   hostname,
		Fragment: parsedUrl.Fragment,
		Original: details.Url,
		Full:     details.Url,
		Password: password,
		Path:     parsedUrl.Path,
		Query:    parsedUrl.RawQuery,
		Scheme:   parsedUrl.Scheme,
		Username: username,
	}

	var port int
	if parsedUrlPort := parsedUrl.Port(); parsedUrlPort != "" {
		port, err = strconv.Atoi(parsedUrlPort)
		if err != nil {
			return nil, fmt.Errorf("failed to part url port: %w", err)
		}

		ecsUrl.Port = port
	} else {
		switch parsedUrl.Scheme {
		case "http":
			port = 80
		case "https":
			port = 443
		}
	}

	ecsServer := &ecs.Target{Address: hostname, Port: port}

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

	base := &ecs.Base{
		Event: &ecs.Event{
			Kind:     "event",
			Category: []string{"network", "web"},
			Type:     []string{"connection"},
		},
		Http: &ecs.Http{
			Request: &ecs.HttpRequest{
				Id:       details.RequestId,
				Method:   details.Method,
				Referrer: details.OriginUrl,
			},
		},
		Network: &ecs.Network{
			Application: "firefox",
			Protocol:    "http",
		},
		Server: ecsServer,
		Url:    ecsUrl,
	}

	return base, nil
}

func ParseNetworkRequest(networkRequest *networkLoggingTypes.NetworkRequest) (*ecs.Base, error) {
	if networkRequest == nil {
		return nil, nil
	}

	base, err := ParseNetworkBase(&networkRequest.NetworkBase)
	if err != nil {
		return nil, fmt.Errorf("failed to extract network base data: %w", err)
	}
	if base == nil {
		return nil, fmt.Errorf("failed to obtain network base data: %w", err)
	}

	parsedTimestamp := time.Unix(networkRequest.TimeStamp, 0).Format(time.RFC3339)
	base.Timestamp = parsedTimestamp

	ecsEvent := base.Event
	if ecsEvent == nil {
		return nil, networkLoggingErrors.ErrNilEcsEvent
	}

	base.Event.Start = parsedTimestamp

	ecsHttp := base.Http
	if ecsHttp == nil {
		return nil, networkLoggingErrors.ErrNilEcsHttp
	}

	ecsHttpRequest := ecsHttp.Request
	if ecsHttpRequest == nil {
		return nil, networkLoggingErrors.ErrNilEcsHttpRequest
	}

	var headerStrings []string
	for _, header := range networkRequest.RequestHeaders {
		headerStrings = append(headerStrings, fmt.Sprintf("%s: %s", header.Name, header.Value))
	}
	if len(headerStrings) != 0 {
		ecsHttpRequest.HttpHeaders = &ecs.HttpHeaders{
			Normalized: strings.Join(headerStrings, "\r\n"),
		}
	}

	return base, nil
}

func ParseNetworkResponse(networkResponse *networkLoggingTypes.NetworkResponse, baseString string) (*ecs.Base, error) {
	if networkResponse == nil {
		return nil, nil
	}

	var base *ecs.Base

	if baseString == "" {
		var err error
		base, err = ParseNetworkBase(&networkResponse.NetworkBase)
		if err != nil {
			return nil, fmt.Errorf("failed to extract network base data: %w", err)
		}
		if base == nil {
			return nil, fmt.Errorf("failed to obtain network basa data: %w", networkLoggingErrors.ErrNilEcsBase)
		}
	} else {
		if err := json.Unmarshal([]byte(baseString), &base); err != nil {
			return nil, fmt.Errorf("failed to unmarshal a network request base string: %w", err)
		}
	}

	parsedTimestamp := time.Unix(networkResponse.TimeStamp, 0).Format(time.RFC3339)
	base.Timestamp = parsedTimestamp

	ecsEvent := base.Event
	if ecsEvent == nil {
		return nil, networkLoggingErrors.ErrNilEcsEvent
	}

	ecsEvent.End = parsedTimestamp

	ecsHttp := base.Http
	if ecsHttp == nil {
		return nil, networkLoggingErrors.ErrNilEcsHttp
	}

	var httpVersion string
	var reasonPhrase string
	if matches := httpVersionPattern.FindStringSubmatch(networkResponse.StatusLine); matches != nil && len(matches) > 1 {
		httpVersion = matches[1]
		reasonPhrase = matches[3]
	} else {
		return nil, networkLoggingErrors.ErrUnmatchedHttpVersion
	}

	ecsNetwork := base.Network
	if ecsNetwork == nil {
		return nil, networkLoggingErrors.ErrNilEcsNetwork
	}

	ecsHttp.Version = httpVersion
	switch httpVersion {
	case "3":
		ecsNetwork.Transport = "udp"
		ecsNetwork.IanaNumber = "17"
	default:
		ecsNetwork.Transport = "tcp"
		ecsNetwork.IanaNumber = "6"
	}

	ecsHttpResponse := &ecs.HttpResponse{StatusCode: networkResponse.StatusCode, ReasonPhrase: reasonPhrase}

	var headerStrings []string
	for _, header := range networkResponse.ResponseHeaders {
		headerStrings = append(headerStrings, fmt.Sprintf("%s: %s", header.Name, header.Value))

		if strings.ToLower(header.Name) == "content-type" {
			ecsHttpResponse.ContentType = header.Value
		}
	}
	if len(headerStrings) != 0 {
		ecsHttpResponse.HttpHeaders = &ecs.HttpHeaders{
			Normalized: strings.Join(headerStrings, "\r\n"),
		}
	}

	ecsHttp.Response = ecsHttpResponse

	return base, nil
}
