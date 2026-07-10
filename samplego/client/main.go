// Command client 는 저장소 README 에서 설명하는 샘플 워크로드(클라이언트)다. README "클라이언트
// > 증명 생성 및 전송"의 선형 5단계(설정 로드 -> 자격증명 획득 -> 증명 형태/만료 결정 -> SigV4
// 서명 + 서버 바인딩 -> 전송)를 순서대로 수행해, 보유한 AWS 신원을 서버에 증명(PoP)하고 서버
// 자체 접근 자격(JWT)을 발급받는다. 선택적으로 발급 토큰을 /verify 로 왕복 확인한다(데모).
//
// 서버가 헥사고날인 것과 달리 이 클라이언트는 절차 중심이라, main 은 각 단계를 담당하는 작은
// 패키지(config/proof/transport)를 순서대로 호출하는 얇은 드라이버다. 신뢰 판단 로직은 없다.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/daengdaenglee/sample-auth-sts/samplego/client/internal/config"
	"github.com/daengdaenglee/sample-auth-sts/samplego/client/internal/proof"
	"github.com/daengdaenglee/sample-auth-sts/samplego/client/internal/transport"
)

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// run 은 클라이언트 파이프라인을 실행한다. 어느 단계든 실패하면 그대로 에러를 전파해 main 이
// 비영 종료하게 한다. 성공하면 발급 토큰과 만료(그리고 --verify 시 클레임)를 표준 출력에 쓴다.
func run(ctx context.Context) error {
	// 1단계. 설정 로드: 서버 주소, 바인딩 값, STS 엔드포인트/리전, 증명 형태를 읽는다.
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// 실행 전체(자격증명 획득 + 서버 요청)를 하나의 데드라인으로 묶는다. 이 ctx 가 이후 모든
	// 단계로 전파되므로, HTTP 다리뿐 아니라 자격증명 획득(SDK 체인의 SSO/AssumeRole/IMDS 호출)
	// 도 무한정 매달리지 않는다.
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	// 2단계. 자격증명 획득: 표준 AWS SDK 자격증명 체인에서 자격증명을 얻는다. 데모/오프라인용
	// static 자격증명을 쓰면 실 AWS 없이 목 STS 로 경로를 구동할 수 있다. 시크릿 키는 로컬에
	// 두고 서명에만 쓰인다.
	creds, err := loadCredentials(ctx, cfg)
	if err != nil {
		return err
	}

	// 3단계. 증명 형태/만료 결정: 현재는 헤더 기반만 지원한다(설정 검증에서 이미 강제). 만료는
	// 헤더 기반이라 X-Amz-Date(서명 시각)를 기준으로 AWS 가 강제하는 고정 구간이 출발점이며,
	// 실제 거부는 서버 측 최대 age 검증과 함께 이뤄진다. 서명 시각은 현재 시각으로 둔다.
	signedAt := time.Now()

	// 4단계. 서명 + 바인딩: GetCallerIdentity 요청에 SigV4 서명을 만들고 서버 바인딩 헤더를
	// 서명 범위에 포함한다.
	env, err := proof.BuildProof(ctx, proof.Input{
		Credentials:  creds,
		Endpoint:     cfg.STSEndpoint,
		Region:       cfg.Region,
		BindingValue: cfg.BindingValue,
		SignedAt:     signedAt,
	})
	if err != nil {
		return err
	}

	// 5단계. 전송: 서명된 요청만 서버 /auth 로 보내 발급 자격을 받는다. 위 ctx 데드라인이 전체를
	// 덮지만, 요청별 안전망으로 http.Client 에도 같은 타임아웃을 걸어 둔다.
	client := transport.New(cfg.ServerAddr, &http.Client{Timeout: cfg.Timeout})
	authResult, err := client.PostAuth(ctx, env)
	if err != nil {
		return err
	}

	fmt.Println("발급 토큰:", authResult.Token)
	fmt.Println("만료:", authResult.ExpiresAt.Format(time.RFC3339))

	// 선택. 데모 왕복: 발급 토큰을 /verify 로 보내 클레임을 되받아 토큰이 실제로 유효함을 보인다.
	if cfg.Verify {
		claims, err := client.PostVerify(ctx, authResult.Token)
		if err != nil {
			return err
		}
		fmt.Println("검증 성공:")
		// 라벨과 클레임 필드를 한 목록으로 묶어 순회한다. 클레임이 늘어도 라벨-필드 짝을
		// 한 곳에서만 맞추면 된다.
		for _, kv := range []struct{ label, value string }{
			{"iss", claims.Issuer},
			{"sub", claims.Subject},
			{"aud", claims.Audience},
			{"exp", claims.ExpiresAt},
			{"iat", claims.IssuedAt},
			{"jti", claims.JTI},
			{"account", claims.Account},
			{"user_id", claims.UserID},
		} {
			fmt.Printf("  %s: %s\n", kv.label, kv.value)
		}
	}

	return nil
}

// loadCredentials 는 설정에 따라 자격증명을 획득한다. static 모드면 주입된 값으로 provider 를
// 만들고, 아니면 표준 SDK 자격증명 체인(환경 변수, EC2 인스턴스 프로파일, IRSA, Pod Identity
// 등)에서 얻는다. GetCallerIdentity 는 별도 IAM 권한이 필요 없으므로 유효한 신원이면 된다.
func loadCredentials(ctx context.Context, cfg config.Config) (aws.Credentials, error) {
	if cfg.StaticCreds {
		provider := credentials.NewStaticCredentialsProvider(cfg.StaticAccessKeyID, cfg.StaticSecretKey, cfg.StaticSessionToken)
		return provider.Retrieve(ctx)
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Region))
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("AWS 설정 로드 실패: %w", err)
	}
	creds, err := awsCfg.Credentials.Retrieve(ctx)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("AWS 자격증명 획득 실패: %w", err)
	}
	return creds, nil
}
