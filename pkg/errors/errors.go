package errors

import "errors"

var (
	ErrNilEcsBase           = errors.New("nil ecs base")
	ErrNilEcsEvent          = errors.New("nil ecs event")
	ErrNilEcsHttp           = errors.New("nil ecs http")
	ErrNilEcsHttpRequest    = errors.New("nil ecs http request")
	ErrNilEcsNetwork        = errors.New("nil ecs network")
	ErrNilEcsServer         = errors.New("nil ecs server")
	ErrNilWebRequestLogging = errors.New("nil web request logging")
	ErrUnmatchedHttpVersion = errors.New("unmatched http version")
)
