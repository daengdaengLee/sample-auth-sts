// Command mocksts 는 실 AWS 없이 로컬 데모를 돌리기 위한 목(mock) AWS STS 다. TLS 로 서빙하며,
// 받은 요청의 SigV4 서명을 검증하지 않고 GetCallerIdentity 성공 XML(고정 ARN/Account/UserId)을
// 돌려준다. 부팅 때 self-signed 인증서를 생성해 그 인증서(PEM)를 신뢰 앵커로 --ca-out 경로에
// 내보내며, 서버는 이를 sts.ca_file(STS_CA_FILE)로 신뢰해 server -> 목 STS 위임의 TLS 를 잇는다.
//
// 이 커맨드는 오로지 데모 전용이다. 서명을 전혀 검증하지 않으므로(누가 서명했든 성공 XML 을
// 돌려준다) 실 배포에서는 절대 쓰지 말 것. 참고 모델은 테스트의 httptest TLS 목 STS 핸들러
// (server/adapter/inbound/auth_test.go, client/internal/e2e/e2e_test.go)다. 표준 라이브러리만
// 쓴다(AWS SDK 도입 없음).
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/daengdaenglee/sample-auth-sts/samplego/server/internal/democert"
)

const (
	// defaultAddr 은 목 STS 가 리슨할 기본 주소다. self-signed 인증서 SAN 에 든 localhost 로
	// 맞춰, 서버/클라이언트가 https://localhost:8443 을 그대로 쓰게 한다.
	defaultAddr = "localhost:8443"

	// defaultCAOut 은 신뢰 앵커(인증서 PEM)를 쓸 기본 경로다. 서버 cwd(samplego/server)에서
	// 목 STS 를 실행하면 이 파일이 서버 cwd 에 놓여, STS_CA_FILE=./mocksts-ca.pem 으로 바로
	// 가리킬 수 있다.
	defaultCAOut = "mocksts-ca.pem"

	// 아래 셋은 GetCallerIdentity 성공 응답에 실을 기본 신원이다. 기본 ARN 은 서버 config.yaml
	// 의 policy.allowed_arns 기본값과 일치시켜, 추가 설정 없이 데모가 통과하게 한다.
	defaultARN     = "arn:aws:iam::123456789012:role/workload"
	defaultAccount = "123456789012"
	defaultUserID  = "AIDAEXAMPLE"

	// shutdownTimeout 은 graceful 셧다운 시 처리 중인 요청이 빠질 때까지 기다리는 최대 시간이다.
	shutdownTimeout = 5 * time.Second
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	addr := flag.String("addr", defaultAddr, "목 STS 가 리슨할 주소(TLS)")
	caOut := flag.String("ca-out", defaultCAOut, "신뢰 앵커(인증서 PEM)를 쓸 경로(서버 STS_CA_FILE 이 가리킬 파일)")
	arn := flag.String("arn", defaultARN, "GetCallerIdentity 로 돌려줄 ARN(서버 policy.allowed_arns 와 일치해야 함)")
	account := flag.String("account", defaultAccount, "GetCallerIdentity 로 돌려줄 Account")
	userID := flag.String("user-id", defaultUserID, "GetCallerIdentity 로 돌려줄 UserId")
	flag.Parse()

	// SAN 에 localhost 와 루프백 IP 를 모두 넣어, 서버/클라이언트가 어느 이름으로 접속하든 TLS
	// 검증이 통과하게 한다(InsecureSkipVerify 를 쓰지 않으므로 SAN 이 맞아야 한다).
	cert, certPEM, err := democert.Generate([]string{"localhost", "127.0.0.1", "::1"})
	if err != nil {
		return err
	}

	// 서버가 신뢰할 수 있도록 인증서(PEM)를 먼저 디스크에 쓴다. 개인키는 쓰지 않는다(메모리에서만
	// TLS 서빙에 쓴다). 0o644: 데모 신뢰 앵커는 비밀이 아니라 공개 인증서다.
	if err := os.WriteFile(*caOut, certPEM, 0o644); err != nil {
		return fmt.Errorf("CA 파일(%s) 쓰기 실패: %w", *caOut, err)
	}

	srv := &http.Server{
		Addr:    *addr,
		Handler: handler(*arn, *account, *userID),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		log.Printf("목 STS 시작(데모 전용, 서명 미검증): https://%s", *addr)
		log.Printf("신뢰 앵커(CA) 파일: %s -- 서버에 STS_CA_FILE 로 지정하세요", *caOut)
		// 인증서/키는 TLSConfig 에 실었으므로 파일 인자는 비워 둔다.
		if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		log.Print("종료 신호 수신, 연결 정리 중")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// successXML 은 GetCallerIdentity 성공 응답(XML) 템플릿이다. 서버 STS 어댑터의
// getCallerIdentityResponse 가 로컬 이름 기준(네임스페이스 무시)으로 Arn/UserId/Account 를
// 뽑으므로, 요소 이름만 맞으면 된다. 값은 데모 운영자가 플래그로 주는 신뢰 입력이라 그대로
// 끼워 넣는다.
const successXML = `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>%s</Arn>
    <UserId>%s</UserId>
    <Account>%s</Account>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>`

// handler 는 메서드/경로와 무관하게(헤더 기반 POST, presigned GET 모두) 서명을 검증하지 않고
// 고정 신원의 GetCallerIdentity 성공 XML 을 돌려준다. 실제 STS 는 서명을 검증하지만, 데모의
// 목 STS 는 왕복 경로를 보이는 것이 목적이라 검증을 생략한다(파일 상단 doc 참고).
func handler(arn, account, userID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 본문을 끝까지 읽어 커넥션 재사용을 돕는다(내용은 검증하지 않는다).
		_, _ = io.Copy(io.Discard, r.Body)
		log.Printf("위임 수신: %s %s", r.Method, r.URL.RequestURI())
		w.Header().Set("Content-Type", "text/xml")
		_, _ = fmt.Fprintf(w, successXML, arn, userID, account)
	}
}
