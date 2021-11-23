package cmdarg

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/v2fly/v2ray-core/v4/common/buf"
)

// LoadArg loads one arg, maybe an remote url, or local file path
func LoadArg(arg string) (out io.Reader, err error) {
	bs, err := LoadArgToBytes(arg)
	if err != nil {
		return nil, err
	}
	out = bytes.NewBuffer(bs)
	return
}

// LoadArgToBytes loads one arg to []byte, maybe an remote url, or local file path
func LoadArgToBytes(arg string) (out []byte, err error) {
	switch {
	default:
		out, err = ioutil.ReadFile(arg)
	}
	if err != nil {
		return
	}
	return
}

// FetchHTTPContent dials https for remote content
func FetchHTTPContent(target string) ([]byte, error) {
	parsedTarget, err := url.Parse(target)
	if err != nil {
		return nil, newError("invalid URL: ", target).Base(err)
	}

	if s := strings.ToLower(parsedTarget.Scheme); s != "http" && s != "https" {
		return nil, newError("invalid scheme: ", parsedTarget.Scheme)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(&http.Request{
		Method: "GET",
		URL:    parsedTarget,
		Close:  true,
	})
	if err != nil {
		return nil, newError("failed to dial to ", target).Base(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, newError("unexpected HTTP status code: ", resp.StatusCode)
	}

	content, err := buf.ReadAllToBytes(resp.Body)
	if err != nil {
		return nil, newError("failed to read HTTP response").Base(err)
	}

	return content, nil
}
