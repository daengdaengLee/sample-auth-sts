package main

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHandler 는 목 STS 핸들러가 메서드/경로와 무관하게(헤더 기반 POST, presigned GET 모두)
// 200 과 GetCallerIdentity 성공 XML 을 돌려주고, 응답이 서버 STS 어댑터가 파싱하는 형식과
// 맞물려 주입한 ARN 을 그대로 담는지 확인한다.
func TestHandler(t *testing.T) {
	const (
		arn     = "arn:aws:iam::123456789012:role/workload"
		account = "123456789012"
		userID  = "AIDAEXAMPLE"
	)
	h := handler(arn, account, userID)

	cases := []struct {
		name   string
		method string
		target string
	}{
		{name: "헤더 기반 POST", method: http.MethodPost, target: "/"},
		{name: "presigned GET", method: http.MethodGet, target: "/?Action=GetCallerIdentity&X-Amz-Algorithm=AWS4-HMAC-SHA256"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.target, strings.NewReader("Action=GetCallerIdentity&Version=2011-06-15"))
			h(rec, req)

			resp := rec.Result()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status=%d, want 200", resp.StatusCode)
			}
			if ct := resp.Header.Get("Content-Type"); ct != "text/xml" {
				t.Errorf("Content-Type=%q, want text/xml", ct)
			}

			body, _ := io.ReadAll(resp.Body)
			// 서버 STS 어댑터가 쓰는 것과 같은 형태로 언마샬해(로컬 이름 기준) 신원이 실렸는지 확인한다.
			var parsed struct {
				XMLName xml.Name `xml:"GetCallerIdentityResponse"`
				Result  struct {
					Arn     string `xml:"Arn"`
					UserID  string `xml:"UserId"`
					Account string `xml:"Account"`
				} `xml:"GetCallerIdentityResult"`
			}
			if err := xml.Unmarshal(body, &parsed); err != nil {
				t.Fatalf("응답 XML 파싱 실패: %v\n본문: %s", err, body)
			}
			if parsed.Result.Arn != arn {
				t.Errorf("Arn=%q, want %q", parsed.Result.Arn, arn)
			}
			if parsed.Result.Account != account {
				t.Errorf("Account=%q, want %q", parsed.Result.Account, account)
			}
			if parsed.Result.UserID != userID {
				t.Errorf("UserId=%q, want %q", parsed.Result.UserID, userID)
			}
		})
	}
}

// TestHandler_escapesXMLMetacharacters 는 신원 값에 XML 메타문자(&/</>)가 들어도 응답이 깨진
// XML 이 아니라 정상 이스케이프돼, 서버 파싱 struct 로 원값이 그대로 복원되는지 확인한다.
// fmt 문자열 조립이었다면 깨진 XML 로 서버 파싱이 실패했을 회귀를 가드한다.
func TestHandler_escapesXMLMetacharacters(t *testing.T) {
	const (
		arn     = "arn:aws:iam::123456789012:role/team&ops<x>"
		account = "123456789012"
		userID  = "AIDA&EXAMPLE"
	)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("Action=GetCallerIdentity&Version=2011-06-15"))
	handler(arn, account, userID)(rec, req)

	resp := rec.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	// 이스케이프된 형태(&amp; 등)로 실려 있어야 하며, 원문 그대로면(깨진 XML) 아래 파싱이 실패한다.
	if strings.Contains(string(body), "team&ops") {
		t.Errorf("응답에 이스케이프되지 않은 & 가 그대로 들어 있음:\n%s", body)
	}

	var parsed struct {
		Result struct {
			Arn     string `xml:"Arn"`
			UserID  string `xml:"UserId"`
			Account string `xml:"Account"`
		} `xml:"GetCallerIdentityResult"`
	}
	if err := xml.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("응답 XML 파싱 실패(이스케이프 누락): %v\n본문: %s", err, body)
	}
	if parsed.Result.Arn != arn {
		t.Errorf("Arn=%q, want %q", parsed.Result.Arn, arn)
	}
	if parsed.Result.UserID != userID {
		t.Errorf("UserId=%q, want %q", parsed.Result.UserID, userID)
	}
}
