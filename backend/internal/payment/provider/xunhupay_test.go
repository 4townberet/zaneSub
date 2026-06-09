package provider

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/payment"
)

// referenceXunhuSign recomputes the expected hash independently of the
// production code, so the test pins the exact algorithm rather than just
// comparing the function to itself.
func referenceXunhuSign(params map[string]string, secret string) string {
	keys := make([]string, 0, len(params))
	for k, v := range params {
		if k == "hash" || v == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+params[k])
	}
	sum := md5.Sum([]byte(strings.Join(parts, "&") + secret))
	return hex.EncodeToString(sum[:])
}

func TestXunhuSignMatchesReference(t *testing.T) {
	t.Parallel()

	params := map[string]string{
		"version":        "1.1",
		"appid":          "201906181467",
		"trade_order_id": "ORDER123",
		"total_fee":      "1.00",
		"title":          "Test",
		"time":           "1700000000",
		"nonce_str":      "abc123",
		"hash":           "ignored",
	}
	secret := "809027fa08a1b855a82750e682866ef2"

	got := xunhuSign(params, secret)
	want := referenceXunhuSign(params, secret)
	if got != want {
		t.Fatalf("xunhuSign mismatch: got %q want %q", got, want)
	}
	if len(got) != 32 {
		t.Fatalf("MD5 hex should be 32 chars, got %d", len(got))
	}
}

func TestXunhuSignExcludesHashAndEmpty(t *testing.T) {
	t.Parallel()

	secret := "secret"
	base := map[string]string{"appid": "1", "total_fee": "2.00"}
	withExtra := map[string]string{
		"appid":      "1",
		"total_fee":  "2.00",
		"hash":       "should_be_ignored",
		"return_url": "", // empty value excluded
	}
	if xunhuSign(base, secret) != xunhuSign(withExtra, secret) {
		t.Fatal("hash and empty values must be excluded from signing")
	}
}

func TestXunhuVerifySign(t *testing.T) {
	t.Parallel()

	secret := "secret"
	params := map[string]string{"appid": "1", "total_fee": "2.00", "trade_order_id": "O1"}
	sign := xunhuSign(params, secret)

	if !xunhuVerifySign(params, secret, sign) {
		t.Fatal("valid signature should verify")
	}
	if xunhuVerifySign(params, secret, sign+"00") {
		t.Fatal("tampered signature must be rejected")
	}
}

func TestXunhuVerifyJSONSignSupportsNestedDataCandidate(t *testing.T) {
	t.Parallel()

	secret := "secret"
	data := `{"status":"OD","open_order_id":"20201381209"}`
	sign := xunhuSign(map[string]string{
		"errcode": "0",
		"errmsg":  "success!",
		"data":    data,
	}, secret)
	body := []byte(`{"errcode":0,"errmsg":"success!","data":` + data + `,"hash":"` + sign + `"}`)

	ok, err := xunhuVerifyJSONSign(body, secret, sign)
	if err != nil {
		t.Fatalf("verify JSON sign failed: %v", err)
	}
	if !ok {
		t.Fatal("expected nested data signature candidate to verify")
	}
}

func TestCreateXunhuPaymentVerifiesResponseAndUsesOpenIDAlias(t *testing.T) {
	t.Parallel()

	secret := "topsecret"
	var gotPath string
	var gotPayload map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Fatalf("Content-Type = %q, want application/json", ct)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatalf("decode json body: %v", err)
		}

		respParams := map[string]string{
			"errcode":    "0",
			"url":        "https://pay.example.com/cashier",
			"url_qrcode": "weixin://wxpay/example",
			"openid":     "20201381209",
			"extra":      "future-field",
		}
		respParams["hash"] = xunhuSign(respParams, secret)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"errcode":    0,
			"url":        respParams["url"],
			"url_qrcode": respParams["url_qrcode"],
			"openid":     respParams["openid"],
			"extra":      respParams["extra"],
			"hash":       respParams["hash"],
		})
	}))
	defer server.Close()

	e := &EasyPay{config: map[string]string{
		"protocol": "xunhupay",
		"pid":      "appid-1",
		"pkey":     secret,
		"apiBase":  server.URL + "/payment/do.html",
	}}
	got, err := e.createXunhuPayment(context.Background(), payment.CreatePaymentRequest{
		OrderID:     "ORDER123",
		Amount:      "12.50",
		Subject:     "Test",
		NotifyURL:   "https://merchant.example.com/notify",
		ReturnURL:   "https://merchant.example.com/return",
		PaymentType: "wxpay",
	})
	if err != nil {
		t.Fatalf("createXunhuPayment failed: %v", err)
	}
	if gotPath != "/payment/do.html" {
		t.Fatalf("request path = %q, want /payment/do.html", gotPath)
	}
	if gotPayload["trade_order_id"] != "ORDER123" {
		t.Fatalf("trade_order_id = %q, want ORDER123", gotPayload["trade_order_id"])
	}
	if got.TradeNo != "20201381209" {
		t.Fatalf("TradeNo = %q, want openid alias", got.TradeNo)
	}
	if got.QRCode != "weixin://wxpay/example" || got.PayURL != "" {
		t.Fatalf("unexpected payment URLs: %+v", got)
	}
}

func TestCreateXunhuPaymentDoesNotSendWechatFieldsForAlipay(t *testing.T) {
	t.Parallel()

	secret := "topsecret"
	var gotPayload map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatalf("decode json body: %v", err)
		}
		respParams := map[string]string{
			"errcode": "0",
			"url":     "https://pay.example.com/alipay",
			"openid":  "20201381209",
		}
		respParams["hash"] = xunhuSign(respParams, secret)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"errcode": 0,
			"url":     respParams["url"],
			"openid":  respParams["openid"],
			"hash":    respParams["hash"],
		})
	}))
	defer server.Close()

	e := &EasyPay{config: map[string]string{
		"protocol": "xunhupay",
		"pid":      "appid-1",
		"pkey":     secret,
		"apiBase":  server.URL + "/payment/do.html",
	}}
	_, err := e.createXunhuPayment(context.Background(), payment.CreatePaymentRequest{
		OrderID:     "ORDER123",
		Amount:      "12.50",
		Subject:     "Test",
		ReturnURL:   "https://merchant.example.com/payment/result?order=ORDER123",
		PaymentType: payment.TypeAlipay,
		IsMobile:    true,
	})
	if err != nil {
		t.Fatalf("createXunhuPayment failed: %v", err)
	}
	for _, field := range []string{"type", "wap_url", "wap_name"} {
		if gotPayload[field] != "" {
			t.Fatalf("%s = %q, want empty for alipay", field, gotPayload[field])
		}
	}
}

func TestCreateXunhuPaymentSendsWAPFieldsForMobileWxpay(t *testing.T) {
	t.Parallel()

	secret := "topsecret"
	var gotPayload map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatalf("decode json body: %v", err)
		}
		respParams := map[string]string{
			"errcode": "0",
			"url":     "https://pay.example.com/wxpay",
			"openid":  "20201381209",
		}
		respParams["hash"] = xunhuSign(respParams, secret)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"errcode": 0,
			"url":     respParams["url"],
			"openid":  respParams["openid"],
			"hash":    respParams["hash"],
		})
	}))
	defer server.Close()

	e := &EasyPay{config: map[string]string{
		"protocol": "xunhupay",
		"pid":      "appid-1",
		"pkey":     secret,
		"apiBase":  server.URL + "/payment/do.html",
	}}
	_, err := e.createXunhuPayment(context.Background(), payment.CreatePaymentRequest{
		OrderID:     "ORDER123",
		Amount:      "12.50",
		Subject:     "Test",
		ReturnURL:   "https://merchant.example.com/payment/result?order=ORDER123",
		PaymentType: payment.TypeWxpay,
		IsMobile:    true,
	})
	if err != nil {
		t.Fatalf("createXunhuPayment failed: %v", err)
	}
	if gotPayload["type"] != "WAP" {
		t.Fatalf("type = %q, want WAP", gotPayload["type"])
	}
	if gotPayload["wap_url"] != "https://merchant.example.com" {
		t.Fatalf("wap_url = %q, want origin URL", gotPayload["wap_url"])
	}
	if gotPayload["wap_name"] != "merchant.example.com" {
		t.Fatalf("wap_name = %q, want hostname", gotPayload["wap_name"])
	}
}

func TestCreateXunhuPaymentRejectsBadResponseHash(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"errcode": 0,
			"url":     "https://pay.example.com/cashier",
			"openid":  "20201381209",
			"hash":    "deadbeef",
		})
	}))
	defer server.Close()

	e := &EasyPay{config: map[string]string{
		"protocol": "xunhupay",
		"pid":      "appid-1",
		"pkey":     "secret",
		"apiBase":  server.URL + "/payment/do.html",
	}}
	_, err := e.createXunhuPayment(context.Background(), payment.CreatePaymentRequest{
		OrderID:   "ORDER123",
		Amount:    "12.50",
		Subject:   "Test",
		NotifyURL: "https://merchant.example.com/notify",
		ReturnURL: "https://merchant.example.com/return",
	})
	if err == nil || !strings.Contains(err.Error(), "invalid response signature") {
		t.Fatalf("expected invalid response signature, got %v", err)
	}
}

func TestQueryXunhuOrderUsesQueryEndpoint(t *testing.T) {
	t.Parallel()

	secret := "topsecret"
	var gotPath string
	var gotForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		gotForm = r.PostForm
		respParams := map[string]string{
			"errcode": "0",
			"errmsg":  "success!",
		}
		respParams["hash"] = xunhuSign(respParams, secret)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"errcode": 0,
			"errmsg":  respParams["errmsg"],
			"data": map[string]any{
				"open_order_id":   "20201381209",
				"total_amount":    "12.50",
				"status":          "OD",
				"transaction_id":  "4200000504202001141029026607",
				"out_trade_order": "ORDER123",
			},
			"hash": respParams["hash"],
		})
	}))
	defer server.Close()

	e := &EasyPay{config: map[string]string{
		"protocol": "xunhupay",
		"pid":      "appid-1",
		"pkey":     secret,
		"apiBase":  server.URL + "/payment/do.html",
	}}
	got, err := e.QueryOrder(context.Background(), "ORDER123")
	if err != nil {
		t.Fatalf("QueryOrder failed: %v", err)
	}
	if gotPath != "/payment/query.html" {
		t.Fatalf("request path = %q, want /payment/query.html", gotPath)
	}
	if gotForm.Get("out_trade_order") != "ORDER123" {
		t.Fatalf("out_trade_order = %q, want ORDER123", gotForm.Get("out_trade_order"))
	}
	if !xunhuVerifySign(map[string]string{
		"appid":           gotForm.Get("appid"),
		"out_trade_order": gotForm.Get("out_trade_order"),
		"time":            gotForm.Get("time"),
		"nonce_str":       gotForm.Get("nonce_str"),
	}, secret, gotForm.Get("hash")) {
		t.Fatal("query signature is invalid")
	}
	if got.Status != "paid" || got.Amount != 12.50 || got.TradeNo != "4200000504202001141029026607" {
		t.Fatalf("unexpected query response: %+v", got)
	}
}

func TestQueryXunhuOrderRejectsBadResponseHash(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"errcode": 0,
			"errmsg":  "success!",
			"data": map[string]any{
				"status":       "OD",
				"total_amount": "12.50",
			},
			"hash": "deadbeef",
		})
	}))
	defer server.Close()

	e := &EasyPay{config: map[string]string{
		"protocol": "xunhupay",
		"pid":      "appid-1",
		"pkey":     "secret",
		"apiBase":  server.URL + "/payment/do.html",
	}}
	_, err := e.QueryOrder(context.Background(), "ORDER123")
	if err == nil || !strings.Contains(err.Error(), "invalid response signature") {
		t.Fatalf("expected invalid response signature, got %v", err)
	}
}

func TestVerifyXunhuNotification(t *testing.T) {
	t.Parallel()

	secret := "topsecret"
	e := &EasyPay{config: map[string]string{
		"protocol": "xunhupay",
		"pid":      "201906181467",
		"pkey":     secret,
	}}

	notify := map[string]string{
		"trade_order_id": "ORDER999",
		"transaction_id": "XH123456",
		"total_fee":      "12.50",
		"status":         "OD",
		"appid":          "201906181467",
	}
	notify["hash"] = xunhuSign(notify, secret)

	form := url.Values{}
	for k, v := range notify {
		form.Set(k, v)
	}
	rawBody := form.Encode()

	got, err := e.verifyXunhuNotification(rawBody)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if got.OrderID != "ORDER999" {
		t.Errorf("OrderID = %q, want ORDER999", got.OrderID)
	}
	if got.TradeNo != "XH123456" {
		t.Errorf("TradeNo = %q, want XH123456", got.TradeNo)
	}
	if got.Status != "success" {
		t.Errorf("Status = %q, want success", got.Status)
	}
	if got.Amount != 12.50 {
		t.Errorf("Amount = %v, want 12.50", got.Amount)
	}
	if got.Metadata["pid"] != "201906181467" {
		t.Errorf("Metadata pid = %q, want 201906181467", got.Metadata["pid"])
	}
}

func TestVerifyXunhuNotificationRejectsTampered(t *testing.T) {
	t.Parallel()

	e := &EasyPay{config: map[string]string{"protocol": "xunhupay", "pkey": "k"}}

	form := url.Values{}
	form.Set("trade_order_id", "O1")
	form.Set("status", "OD")
	form.Set("hash", "deadbeef")

	if _, err := e.verifyXunhuNotification(form.Encode()); err == nil {
		t.Fatal("expected invalid-signature error for tampered notification")
	}
}

func TestVerifyXunhuNotificationFailedStatus(t *testing.T) {
	t.Parallel()

	secret := "k"
	e := &EasyPay{config: map[string]string{"protocol": "xunhupay", "pkey": secret}}

	notify := map[string]string{"trade_order_id": "O1", "status": "WP", "total_fee": "1.00"}
	notify["hash"] = xunhuSign(notify, secret)
	form := url.Values{}
	for k, v := range notify {
		form.Set(k, v)
	}

	got, err := e.verifyXunhuNotification(form.Encode())
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if got.Status != "failed" {
		t.Errorf("Status = %q, want failed", got.Status)
	}
}

func TestEasyPayIsXunhuPay(t *testing.T) {
	t.Parallel()

	cases := map[string]bool{
		"xunhupay": true,
		"XunhuPay": true,
		"epay":     false,
		"":         false,
	}
	for proto, want := range cases {
		e := &EasyPay{config: map[string]string{"protocol": proto}}
		if e.isXunhuPay() != want {
			t.Errorf("isXunhuPay(%q) = %v, want %v", proto, e.isXunhuPay(), want)
		}
	}
}
