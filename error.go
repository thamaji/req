package req

import (
	"io"
	"net/http"
)

var MaxErrorBodySize = 4096

type Error struct {
	message string

	Method     string
	URL        string
	StatusCode int
	Status     string
	Header     http.Header
	Body       []byte // max 4096 byte (maxErrorBodySize)
}

func (err *Error) Error() string {
	return err.message
}

func NewError(resp *http.Response, detail string) error {
	url := resp.Request.URL.String()

	message := "req: invalid response."
	if detail != "" {
		message += " " + detail + "."
	}
	message += " " + resp.Request.Method + " " + url

	size := int(resp.ContentLength)
	if size < 0 || size > MaxErrorBodySize {
		size = MaxErrorBodySize
	}
	buf := make([]byte, size)
	n, _ := io.ReadFull(resp.Body, buf)

	return &Error{
		message:    message,
		Method:     resp.Request.Method,
		URL:        url,
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Header:     resp.Header,
		Body:       buf[:n],
	}
}

func IsStatusCode(err error, statusCode int) bool {
	e, ok := err.(*Error)
	if !ok {
		return false
	}
	return e.StatusCode == statusCode
}

func GetMethod(err error) (string, bool) {
	e, ok := err.(*Error)
	if !ok {
		return "", false
	}
	return e.Method, true
}

func GetURL(err error) (string, bool) {
	e, ok := err.(*Error)
	if !ok {
		return "", false
	}
	return e.URL, true
}

func GetStatusCode(err error) (int, bool) {
	e, ok := err.(*Error)
	if !ok {
		return 0, false
	}
	return e.StatusCode, true
}

func GetStatus(err error) (string, bool) {
	e, ok := err.(*Error)
	if !ok {
		return "", false
	}
	return e.Status, true
}

func GetBody(err error) ([]byte, bool) {
	e, ok := err.(*Error)
	if !ok {
		return nil, false
	}
	return e.Body, true
}

func GetHeader(err error) (http.Header, bool) {
	e, ok := err.(*Error)
	if !ok {
		return nil, false
	}
	return e.Header, true
}
