package validator

import (
	"errors"
	"mime"
	"net/http"
	"strconv"

	"github.com/thamaji/req"
)

func StatusCode(statusCode int) req.Validator {
	return func(resp *http.Response) error {
		if resp.StatusCode != statusCode {
			return req.NewError(resp, "Status "+strconv.Itoa(resp.StatusCode))
		}
		return nil
	}
}

func StatusCodeRange(start, end int) req.Validator {
	return func(resp *http.Response) error {
		if resp.StatusCode < start && resp.StatusCode >= end {
			return req.NewError(resp, "Status "+strconv.Itoa(resp.StatusCode))
		}
		return nil
	}
}

func ContentType(contentType string) req.Validator {
	return func(resp *http.Response) error {
		expected, _, err := mime.ParseMediaType(contentType)
		if err != nil {
			return errors.New("validator: cannot parse Content-Type " + contentType)
		}

		contentType := resp.Header.Get("Content-Type")

		actual, _, err := mime.ParseMediaType(contentType)
		if err != nil {
			return req.NewError(resp, "Content-Type "+contentType)
		}

		if expected != actual {
			return req.NewError(resp, "Content-Type "+actual)
		}
		return nil
	}
}
