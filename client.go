package deco

import (
	"crypto/md5"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"

	"github.com/mrmarble/deco/utils"
)

const (
	// userName is the default (hardcoded) username
	userName = "admin"
)

var baseURL = url.URL{
	Scheme: "http",
	Path:   "/cgi-bin/luci/",
}

// Client is a client for sending requests to the Deco-m4 API
type Client struct {
	c        *http.Client
	aes      *utils.AESKey
	rsa      *rsa.PublicKey
	hash     string
	stok     string
	sequence uint
}

// ClientListResp is the structure of the client_list endpoint
type ClientListResp struct {
	ErrorCode int `json:"error_code"`
	Result    struct {
		ClientList []struct {
			AccessHost     string `json:"access_host"`
			ClientMesh     bool   `json:"client_mesh"`
			ClientType     string `json:"client_type"`
			ConnectionType string `json:"band5"`
			DownSpeed      uint   `json:"down_speed"`
			EnablePriority bool   `json:"enable_priority"`
			Interface      string `json:"interface"`
			IP             string `json:"ip"`
			MAC            string `json:"mac"`
			Name           string `json:"name"`
			Online         bool   `json:"online"`
			OwnerID        string `json:"owner_id"`
			RemainTime     uint   `json:"remain_time"`
			SpaceID        string `json:"space_id"`
			UpSpeed        uint   `json:"up_speed"`
			WireType       string `json:"wire_type"`
		} `json:"client_list"`
	} `json:"result"`
}

// PerfResp is the structure of the performance endpoint
type PerfResp struct {
	ErrorCode int `json:"error_code"`
	Result    struct {
		CPU float32 `json:"cpu_usage"`
		MEM float32 `json:"mem_usage"`
	} `json:"result"`
}

// New creates a new Go client for the Deco-m4 API
func New(target string) *Client {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Timeout: 10 * time.Second, Jar: jar}

	baseURL.Host = target

	return &Client{
		c: c,
	}
}

// Authenticate will generate the keys needed for the communication with the router.
func (c *Client) Authenticate(password string) error {
	c.aes = utils.GenerateAESKey()
	c.hash = fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s%s", userName, password))))

	passwordKey, err := c.getPasswordKey()
	if err != nil {
		return err
	}

	sessionKey, sequence, err := c.getSessionKey()
	if err != nil {
		return err
	}
	c.rsa = sessionKey
	c.sequence = sequence

	encryptedPassword, err := utils.EncryptRsa(password, passwordKey)
	if err != nil {
		return err
	}

	loginReq := loginRequest{
		Operation: "login",
		Params: loginParams{
			Password: string(encryptedPassword),
		},
	}

	loginJSON, err := json.Marshal(loginReq)
	if err != nil {
		return err
	}
	args := EndpointArgs{
		form: "login",
	}
	var result loginResponse
	err = c.doEncryptedPost(";stok=/login", args, loginJSON, true, &result)
	if err != nil {
		return err
	}
	c.stok = result.Result.Stok
	return nil
}

// Performance returns the current cpu and mem usage.
func (c *Client) Performance() (*PerfResp, error) {
	var result PerfResp
	err := c.doEncryptedPost(fmt.Sprintf(";stok=%s/admin/network", c.stok), EndpointArgs{form: "performance"}, readBody, false, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// ClientList returns the list of connected devices
func (c *Client) ClientList() (*ClientListResp, error) {
	var result ClientListResp
	request := request{
		Operation: "read",
		Params:    map[string]string{"device_mac": "default"},
	}
	jsonRequest, _ := json.Marshal(request)
	err := c.doEncryptedPost(fmt.Sprintf(";stok=%s/admin/client", c.stok), EndpointArgs{form: "client_list"}, jsonRequest, false, &result)
	if err != nil {
		return nil, err
	}
	for index := range result.Result.ClientList {
		name, err := base64.StdEncoding.DecodeString(result.Result.ClientList[index].Name)
		if err == nil {
			result.Result.ClientList[index].Name = string(name)
		}
	}
	return &result, nil
}

// Custom lets you make a custom request
func (c *Client) Custom(path string, params EndpointArgs, body []byte) (interface{}, error) {
	var result interface{}
	err := c.doEncryptedPost(fmt.Sprintf(";stok=%s%s", c.stok, path), params, body, false, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}
