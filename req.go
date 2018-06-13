package req

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/thamaji/ioutils"
)

func URL(url string, elem ...string) string {
	if len(elem) <= 0 {
		return url
	}
	return strings.TrimSuffix(url, "/") + "/" + strings.TrimPrefix(path.Join(elem...), "/")
}

type Body func() (io.Reader, error)

func BodyJSON(v interface{}) Body {
	return func() (io.Reader, error) {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		return bytes.NewReader(b), nil
	}
}

func BodyString(v string) Body {
	return func() (io.Reader, error) {
		return strings.NewReader(v), nil
	}
}

func BodyBytes(v []byte) Body {
	return func() (io.Reader, error) {
		return bytes.NewReader(v), nil
	}
}

func BodyReader(v io.Reader) Body {
	return func() (io.Reader, error) {
		return v, nil
	}
}

type Option func(*http.Request) *http.Request

func Header(key string, values ...string) Option {
	return func(req *http.Request) *http.Request {
		if len(values) <= 0 {
			return req
		}

		if req.Header == nil {
			req.Header = http.Header{}
		}

		req.Header.Set(key, values[0])
		for _, value := range values[1:] {
			req.Header.Add(key, value)
		}

		return req
	}
}

func ContentType(contentType string) Option {
	return Header("Content-Type", contentType)
}

func Accept(contentTypes ...string) Option {
	return Header("Accept", strings.Join(contentTypes, ","))
}

func ContentLength(length int) Option {
	return Header("Content-Length", strconv.Itoa(length))
}

func UserAgent(userAgent string) Option {
	return Header("User-Agent", userAgent)
}

func Query(key string, values ...string) Option {
	return func(req *http.Request) *http.Request {
		if len(values) <= 0 {
			return req
		}

		query := req.URL.Query()

		query.Set(key, values[0])
		for _, value := range values[1:] {
			query.Add(key, value)
		}

		req.URL.RawQuery = query.Encode()

		return req
	}
}

func QueryInt(key string, values ...int) Option {
	strValues := make([]string, 0, len(values))
	for _, value := range values {
		strValues = append(strValues, strconv.Itoa(value))
	}
	return Query(key, strValues...)
}

func QueryInt32(key string, values ...int32) Option {
	strValues := make([]string, 0, len(values))
	for _, value := range values {
		strValues = append(strValues, strconv.FormatInt(int64(value), 10))
	}
	return Query(key, strValues...)
}

func QueryInt64(key string, values ...int64) Option {
	strValues := make([]string, 0, len(values))
	for _, value := range values {
		strValues = append(strValues, strconv.FormatInt(value, 10))
	}
	return Query(key, strValues...)
}

func QueryFloat32(key string, values ...float32) Option {
	strValues := make([]string, 0, len(values))
	for _, value := range values {
		strValues = append(strValues, strconv.FormatFloat(float64(value), 'f', -1, 32))
	}
	return Query(key, strValues...)
}

func QueryFloat64(key string, values ...float64) Option {
	strValues := make([]string, 0, len(values))
	for _, value := range values {
		strValues = append(strValues, strconv.FormatFloat(value, 'f', -1, 64))
	}
	return Query(key, strValues...)
}

func QueryBool(key string, values ...bool) Option {
	strValues := make([]string, 0, len(values))
	for _, value := range values {
		strValues = append(strValues, strconv.FormatBool(value))
	}
	return Query(key, strValues...)
}

func BasicAuth(username, password string) Option {
	return func(req *http.Request) *http.Request {
		if req.Header == nil {
			req.Header = http.Header{}
		}

		req.SetBasicAuth(username, password)

		return req
	}
}

func BearerToken(token string) Option {
	return func(req *http.Request) *http.Request {
		if req.Header == nil {
			req.Header = http.Header{}
		}

		req.Header.Set("Authorization", "Bearer "+token)

		return req
	}
}

func NewRequest(method string, url string, body Body, options ...Option) (*http.Request, error) {
	var err error
	var reader io.Reader

	if body != nil {
		reader, err = body()
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return nil, err
	}

	for _, option := range options {
		req = option(req)
	}

	return req, nil
}

type Request struct {
	req *http.Request
	err error

	Client    *http.Client
	validator Validator
}

var DefaultClient *http.Client

type Validator func(*http.Response) error

var DefaultValidator = func(resp *http.Response) error {
	if resp.StatusCode < 200 && resp.StatusCode >= 300 {
		return errors.New("failed to request [" + resp.Request.Method + "] " + resp.Request.URL.String() + ": " + resp.Status)
	}

	return nil
}

func Get(url string, body Body, options ...Option) *Request {
	req, err := NewRequest(http.MethodGet, url, body, options...)
	return &Request{req: req, err: err, Client: DefaultClient, validator: DefaultValidator}
}

func Head(url string, body Body, options ...Option) *Request {
	req, err := NewRequest(http.MethodHead, url, body, options...)
	return &Request{req: req, err: err, Client: DefaultClient, validator: DefaultValidator}
}

func Post(url string, body Body, options ...Option) *Request {
	req, err := NewRequest(http.MethodPost, url, body, options...)
	return &Request{req: req, err: err, Client: DefaultClient, validator: DefaultValidator}
}

func Put(url string, body Body, options ...Option) *Request {
	req, err := NewRequest(http.MethodPut, url, body, options...)
	return &Request{req: req, err: err, Client: DefaultClient, validator: DefaultValidator}
}

func Patch(url string, body Body, options ...Option) *Request {
	req, err := NewRequest(http.MethodPatch, url, body, options...)
	return &Request{req: req, err: err, Client: DefaultClient, validator: DefaultValidator}
}

func Delete(url string, body Body, options ...Option) *Request {
	req, err := NewRequest(http.MethodDelete, url, body, options...)
	return &Request{req: req, err: err, Client: DefaultClient, validator: DefaultValidator}
}

func Connect(url string, body Body, options ...Option) *Request {
	req, err := NewRequest(http.MethodConnect, url, body, options...)
	return &Request{req: req, err: err, Client: DefaultClient, validator: DefaultValidator}
}

func Options(url string, body Body, options ...Option) *Request {
	req, err := NewRequest(http.MethodOptions, url, body, options...)
	return &Request{req: req, err: err, Client: DefaultClient, validator: DefaultValidator}
}

func Trace(url string, body Body, options ...Option) *Request {
	req, err := NewRequest(http.MethodTrace, url, body, options...)
	return &Request{req: req, err: err, Client: DefaultClient, validator: DefaultValidator}
}

func (req *Request) Do() (*http.Response, error) {
	if req.err != nil {
		return nil, req.err
	}

	client := req.Client
	if client == nil {
		client = DefaultClient
	}

	resp, err := client.Do(req.req)
	if err != nil {
		return nil, err
	}

	body := resp.Body
	resp.Body = ioutils.NewReadCloser(body, ioutils.CloserFunc(func() error {
		io.Copy(ioutil.Discard, body)
		return body.Close()
	}))

	if req.validator != nil {
		if err = req.validator(resp); err != nil {
			resp.Body.Close()
			return nil, err
		}
	}

	return resp, nil
}

func (req *Request) Validator(validators ...Validator) *Request {
	req.validator = func(resp *http.Response) error {
		for _, validator := range validators {
			if err := validator(resp); err != nil {
				return err
			}
		}
		return nil
	}
	return req
}

const maxErrorBodySize = 4096

type ValidateError struct {
	message string

	Method     string
	URL        string
	StatusCode int
	Status     string
	Header     http.Header
	Body       []byte // max 4096 byte (maxErrorBodySize)
}

func (err *ValidateError) Error() string {
	return err.message
}

func validateError(resp *http.Response, detail string) error {
	message := "invalid response [" + resp.Request.Method + "] " + resp.Request.URL.String()
	if detail != "" {
		message = message + ": " + detail
	}

	size := resp.ContentLength
	if size < 0 || size > maxErrorBodySize {
		size = maxErrorBodySize
	}
	buf := make([]byte, int(size))
	n, _ := io.ReadFull(resp.Body, buf)

	return &ValidateError{
		message:    message,
		Method:     resp.Request.Method,
		URL:        resp.Request.URL.String(),
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Header:     resp.Header,
		Body:       buf[:n],
	}
}

func IsStatusCode(err error, statusCode int) bool {
	validateError, ok := err.(*ValidateError)
	if !ok {
		return false
	}
	return validateError.StatusCode == statusCode
}

func GetMethod(err error) (string, bool) {
	validateError, ok := err.(*ValidateError)
	if !ok {
		return "", false
	}
	return validateError.Method, true
}

func GetURL(err error) (string, bool) {
	validateError, ok := err.(*ValidateError)
	if !ok {
		return "", false
	}
	return validateError.URL, true
}

func GetStatusCode(err error) (int, bool) {
	validateError, ok := err.(*ValidateError)
	if !ok {
		return 0, false
	}
	return validateError.StatusCode, true
}

func GetStatus(err error) (string, bool) {
	validateError, ok := err.(*ValidateError)
	if !ok {
		return "", false
	}
	return validateError.Status, true
}

func GetBody(err error) ([]byte, bool) {
	validateError, ok := err.(*ValidateError)
	if !ok {
		return nil, false
	}
	return validateError.Body, true
}

func GetHeader(err error) (http.Header, bool) {
	validateError, ok := err.(*ValidateError)
	if !ok {
		return nil, false
	}
	return validateError.Header, true
}

func ValidateStatusCode(statusCode int) Validator {
	return func(resp *http.Response) error {
		if resp.StatusCode != statusCode {
			return validateError(resp, "bad status "+resp.Status)
		}
		return nil
	}
}

func ValidateStatusCodeRange(start, end int) Validator {
	return func(resp *http.Response) error {
		if resp.StatusCode < start && resp.StatusCode >= end {
			return validateError(resp, "bad status "+resp.Status)
		}
		return nil
	}
}

func ValidateContentType(contentType string) Validator {
	return func(resp *http.Response) error {
		expected, _, err := mime.ParseMediaType(contentType)
		if err != nil {
			return errors.New("failed to parse expected Content-Type: " + contentType)
		}

		actual, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if err != nil {
			return validateError(resp, "failed to parse Content-Type "+resp.Header.Get("Content-Type"))
		}

		if expected != actual {
			return validateError(resp, " bad Content-Type "+actual)
		}
		return nil
	}
}

func (req *Request) Done() error {
	resp, err := req.Do()
	if err != nil {
		return err
	}

	resp.Body.Close()
	return nil
}

func (req *Request) Open() (io.ReadCloser, error) {
	resp, err := req.Do()
	if err != nil {
		return nil, err
	}

	return resp.Body, nil
}

func (req *Request) Fetch() ([]byte, error) {
	resp, err := req.Do()
	if err != nil {
		return nil, err
	}

	bytes, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	return bytes, err
}

func (req *Request) FetchJSON(v interface{}) error {
	resp, err := req.Do()
	if err != nil {
		return err
	}

	err = json.NewDecoder(resp.Body).Decode(v)
	resp.Body.Close()
	return err
}

func init() {
	transport := *(http.DefaultTransport.(*http.Transport))
	transport.MaxIdleConns = 100
	transport.MaxIdleConnsPerHost = 50
	DefaultClient = &http.Client{Transport: &transport}
}
