package provider

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/payment"
)

// XunhuPay protocol support.
//
// XunhuPay is an aggregation gateway that speaks a different wire protocol than
// the Rainbow EasyPay (epay) protocol implemented in easypay.go. It is exposed
// to admins as the EasyPay provider with config["protocol"] == "xunhupay", so
// all routing / snapshot / visible-method logic continues to treat it as
// TypeEasyPay. Only the on-wire request/response shape differs.
//
// Credential mapping (admin reuses existing EasyPay config keys):
//   - pid     -> appid
//   - pkey    -> appsecret
//   - apiBase -> full gateway URL, e.g. https://api.xunhupay.com/payment/do.html
const (
	xunhuProtocol      = "xunhupay"
	xunhuVersion       = "1.1"
	xunhuTradeStatusOK = "OD"
	xunhuHTTPTimeout   = 30 * time.Second
)

// isXunhuPay reports whether this EasyPay instance is configured for the
// XunhuPay protocol rather than the default epay protocol.
func (e *EasyPay) isXunhuPay() bool {
	return strings.EqualFold(strings.TrimSpace(e.config["protocol"]), xunhuProtocol)
}

// xunhuGateway returns the configured gateway URL verbatim. Unlike epay, the
// admin enters the full endpoint, so no path joining is done.
func (e *EasyPay) xunhuGateway() string {
	return strings.TrimSpace(e.config["apiBase"])
}

func (e *EasyPay) xunhuQueryGateway() string {
	gateway := e.xunhuGateway()
	parsed, err := url.Parse(gateway)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return strings.TrimRight(gateway, "/") + "/payment/query.html"
	}
	path := strings.TrimRight(parsed.Path, "/")
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, "/payment/do.html"):
		parsed.Path = path[:len(path)-len("/payment/do.html")] + "/payment/query.html"
	case strings.HasSuffix(lower, "/do.html"):
		parsed.Path = path[:len(path)-len("/do.html")] + "/query.html"
	case !strings.HasSuffix(lower, "/query.html"):
		parsed.Path = strings.TrimRight(path, "/") + "/payment/query.html"
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

// createXunhuPayment initiates a payment via the XunhuPay /payment/do.html API.
func (e *EasyPay) createXunhuPayment(ctx context.Context, req payment.CreatePaymentRequest) (*payment.CreatePaymentResponse, error) {
	notifyURL, returnURL := e.resolveURLs(req)

	params := map[string]string{
		"version":        xunhuVersion,
		"appid":          e.config["pid"],
		"trade_order_id": req.OrderID,
		"total_fee":      req.Amount,
		"title":          req.Subject,
		"time":           strconv.FormatInt(time.Now().Unix(), 10),
		"notify_url":     notifyURL,
		"return_url":     returnURL,
		"nonce_str":      xunhuNonceStr(req.OrderID),
	}
	if xunhuNeedsWAPFields(req) {
		wapURL := xunhuOriginURL(returnURL, notifyURL)
		params["type"] = "WAP"
		if wapURL != "" {
			params["wap_url"] = wapURL
		}
		if wapName := xunhuWAPName(wapURL); wapName != "" {
			params["wap_name"] = wapName
		}
	}
	params["hash"] = xunhuSign(params, e.config["pkey"])

	body, err := e.postXunhuJSON(ctx, e.xunhuGateway(), params)
	if err != nil {
		return nil, fmt.Errorf("xunhupay create: %w", err)
	}

	var resp struct {
		ErrCode int                 `json:"errcode"`
		ErrMsg  string              `json:"errmsg"`
		URL     string              `json:"url"`        // H5 cashier URL
		URLQR   string              `json:"url_qrcode"` // QR code page / content
		OrderID xunhuFlexibleString `json:"oderid"`     // upstream trade id (note: API spells it "oderid")
		OpenID  xunhuFlexibleString `json:"openid"`     // documented legacy alias for the upstream order id
		Hash    string              `json:"hash"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("xunhupay parse: %s", summarizeEasyPayResponse(body))
	}
	if resp.ErrCode != 0 {
		msg := strings.TrimSpace(resp.ErrMsg)
		if msg == "" {
			msg = summarizeEasyPayResponse(body)
		}
		return nil, fmt.Errorf("xunhupay error (errcode=%d): %s", resp.ErrCode, msg)
	}
	if strings.TrimSpace(resp.Hash) == "" {
		return nil, fmt.Errorf("xunhupay missing response hash")
	}
	signOK, signErr := xunhuVerifyJSONSign(body, e.config["pkey"], resp.Hash)
	if signErr != nil {
		return nil, fmt.Errorf("xunhupay parse: %s", summarizeEasyPayResponse(body))
	}
	if !signOK {
		return nil, fmt.Errorf("xunhupay invalid response signature")
	}

	tradeNo := strings.TrimSpace(string(resp.OrderID))
	if tradeNo == "" {
		tradeNo = strings.TrimSpace(string(resp.OpenID))
	}
	out := &payment.CreatePaymentResponse{TradeNo: tradeNo}
	if req.IsMobile {
		out.PayURL = resp.URL
	} else {
		out.QRCode = resp.URLQR
		if out.QRCode != "" {
			out.QRCodeType = "image"
		}
		if out.QRCode == "" {
			out.PayURL = resp.URL
		}
	}
	return out, nil
}

func xunhuNeedsWAPFields(req payment.CreatePaymentRequest) bool {
	return req.IsMobile && payment.GetBasePaymentType(req.PaymentType) == payment.TypeWxpay
}

func xunhuOriginURL(rawURLs ...string) string {
	for _, raw := range rawURLs {
		parsed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			continue
		}
		return parsed.Scheme + "://" + parsed.Host
	}
	return ""
}

func xunhuWAPName(origin string) string {
	parsed, err := url.Parse(strings.TrimSpace(origin))
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	name := parsed.Hostname()
	if len(name) > 32 {
		return name[:32]
	}
	return name
}

func (e *EasyPay) queryXunhuOrder(ctx context.Context, tradeNo string) (*payment.QueryOrderResponse, error) {
	params := map[string]string{
		"appid":           e.config["pid"],
		"out_trade_order": tradeNo,
		"time":            strconv.FormatInt(time.Now().Unix(), 10),
		"nonce_str":       xunhuNonceStr(tradeNo),
	}
	params["hash"] = xunhuSign(params, e.config["pkey"])

	body, err := e.post(ctx, e.xunhuQueryGateway(), params)
	if err != nil {
		return nil, fmt.Errorf("xunhupay query: %w", err)
	}

	var resp struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
		Data    struct {
			OpenOrderID   xunhuFlexibleString `json:"open_order_id"`
			TotalAmount   string              `json:"total_amount"`
			TotalFee      string              `json:"total_fee"`
			Status        string              `json:"status"`
			TransactionID xunhuFlexibleString `json:"transaction_id"`
			OutTradeOrder string              `json:"out_trade_order"`
		} `json:"data"`
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("xunhupay parse query: %s", summarizeEasyPayResponse(body))
	}
	if resp.ErrCode != 0 {
		msg := strings.TrimSpace(resp.ErrMsg)
		if msg == "" {
			msg = summarizeEasyPayResponse(body)
		}
		return nil, fmt.Errorf("xunhupay query error (errcode=%d): %s", resp.ErrCode, msg)
	}
	if strings.TrimSpace(resp.Hash) == "" {
		return nil, fmt.Errorf("xunhupay query missing response hash")
	}
	signOK, signErr := xunhuVerifyJSONSign(body, e.config["pkey"], resp.Hash)
	if signErr != nil || !signOK {
		return nil, fmt.Errorf("xunhupay query invalid response signature")
	}

	status := payment.ProviderStatusPending
	if resp.Data.Status == xunhuTradeStatusOK {
		status = payment.ProviderStatusPaid
	}
	amountText := strings.TrimSpace(resp.Data.TotalAmount)
	if amountText == "" {
		amountText = strings.TrimSpace(resp.Data.TotalFee)
	}
	amount, _ := strconv.ParseFloat(amountText, 64)
	trade := strings.TrimSpace(string(resp.Data.TransactionID))
	if trade == "" {
		trade = strings.TrimSpace(string(resp.Data.OpenOrderID))
	}

	return &payment.QueryOrderResponse{
		TradeNo:  trade,
		Status:   status,
		Amount:   amount,
		Metadata: e.MerchantIdentityMetadata(),
	}, nil
}

func (e *EasyPay) postXunhuJSON(ctx context.Context, endpoint string, params map[string]string) ([]byte, error) {
	payload, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := e.httpClient
	if client == nil {
		client = &http.Client{Timeout: xunhuHTTPTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxEasypayResponseSize))
	if err != nil {
		return nil, err
	}
	return body, nil
}

// verifyXunhuNotification parses and verifies a XunhuPay async notify callback.
func (e *EasyPay) verifyXunhuNotification(rawBody string) (*payment.PaymentNotification, error) {
	values, err := url.ParseQuery(rawBody)
	if err != nil {
		return nil, fmt.Errorf("xunhupay parse notify: %w", err)
	}
	params := make(map[string]string, len(values))
	for k := range values {
		params[k] = values.Get(k)
	}

	sign := params["hash"]
	if sign == "" {
		return nil, fmt.Errorf("xunhupay missing hash")
	}
	if !xunhuVerifySign(params, e.config["pkey"], sign) {
		return nil, fmt.Errorf("xunhupay invalid signature")
	}

	status := payment.ProviderStatusFailed
	if params["status"] == xunhuTradeStatusOK || params["trade_status"] == xunhuTradeStatusOK {
		status = payment.ProviderStatusSuccess
	}
	amount, _ := strconv.ParseFloat(params["total_fee"], 64)

	metadata := e.MerchantIdentityMetadata()
	if appid := strings.TrimSpace(params["appid"]); appid != "" {
		if metadata == nil {
			metadata = map[string]string{}
		}
		// Snapshot consistency uses "pid"; XunhuPay's appid maps to it.
		metadata["pid"] = appid
	}

	return &payment.PaymentNotification{
		TradeNo:  params["transaction_id"],
		OrderID:  params["trade_order_id"],
		Amount:   amount,
		Status:   status,
		RawData:  rawBody,
		Metadata: metadata,
	}, nil
}

// xunhuSign computes the XunhuPay MD5 hash: sort non-empty params (excluding
// "hash") by key, join as k=v&k=v..., append the app secret directly, MD5,
// lowercase hex. Same algorithm family as easyPaySign, different excluded key.
func xunhuSign(params map[string]string, appsecret string) string {
	keys := make([]string, 0, len(params))
	for k, v := range params {
		if k == "hash" || v == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf strings.Builder
	for i, k := range keys {
		if i > 0 {
			_ = buf.WriteByte('&')
		}
		_, _ = buf.WriteString(k + "=" + params[k])
	}
	_, _ = buf.WriteString(appsecret)
	hash := md5.Sum([]byte(buf.String()))
	return hex.EncodeToString(hash[:])
}

func xunhuVerifySign(params map[string]string, appsecret, sign string) bool {
	return hmac.Equal([]byte(xunhuSign(params, appsecret)), []byte(sign))
}

func xunhuVerifyJSONSign(body []byte, appsecret, sign string) (bool, error) {
	candidates, err := xunhuJSONSignParamCandidates(body)
	if err != nil {
		return false, err
	}
	for i, params := range candidates {
		if xunhuVerifySign(params, appsecret, sign) {
			if i > 0 {
				slog.Warn("xunhupay response signature matched fallback JSON canonicalization",
					"candidate_index", i,
					"candidate_count", len(candidates))
			}
			return true, nil
		}
	}
	return false, nil
}

func xunhuJSONSignParamCandidates(body []byte) ([]map[string]string, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	scalarParams := make(map[string]string, len(raw))
	jsonParams := make(map[string]string, len(raw))
	hasComposite := false
	for key, data := range raw {
		if strings.EqualFold(key, "hash") {
			continue
		}
		if value, ok := xunhuJSONScalarString(data); ok {
			scalarParams[key] = value
			jsonParams[key] = value
			continue
		}
		if value, ok := xunhuJSONCompactString(data); ok {
			jsonParams[key] = value
			hasComposite = true
		}
	}
	candidates := []map[string]string{scalarParams}
	if hasComposite {
		candidates = append(candidates, jsonParams)
	}
	return candidates, nil
}

func xunhuJSONScalarString(data json.RawMessage) (string, bool) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		return "", true
	}
	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		return text, true
	}
	var number json.Number
	decoder := json.NewDecoder(strings.NewReader(trimmed))
	decoder.UseNumber()
	if err := decoder.Decode(&number); err == nil {
		return number.String(), true
	}
	var boolean bool
	if err := json.Unmarshal(data, &boolean); err == nil {
		return strconv.FormatBool(boolean), true
	}
	return "", false
}

func xunhuJSONCompactString(data json.RawMessage) (string, bool) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || (trimmed[0] != '{' && trimmed[0] != '[') {
		return "", false
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, data); err != nil {
		return "", false
	}
	return buf.String(), true
}

// xunhuNonceStr derives a deterministic-but-unique nonce from the order ID and
// current time, avoiding a crypto/rand dependency for a non-secret field.
func xunhuNonceStr(orderID string) string {
	seed := orderID + strconv.FormatInt(time.Now().UnixNano(), 10)
	sum := md5.Sum([]byte(seed))
	return hex.EncodeToString(sum[:])
}

type xunhuFlexibleString string

func (s *xunhuFlexibleString) UnmarshalJSON(data []byte) error {
	text := strings.TrimSpace(string(data))
	if text == "" || text == "null" {
		*s = ""
		return nil
	}
	if len(text) >= 2 && text[0] == '"' && text[len(text)-1] == '"' {
		var value string
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		*s = xunhuFlexibleString(value)
		return nil
	}
	if !xunhuFlexibleStringUnquotedValueIsValid(text) {
		return fmt.Errorf("invalid xunhupay string value: %s", text)
	}
	*s = xunhuFlexibleString(text)
	return nil
}

func xunhuFlexibleStringUnquotedValueIsValid(text string) bool {
	if _, err := strconv.ParseFloat(text, 64); err == nil {
		return true
	}
	return net.ParseIP(text) != nil
}
