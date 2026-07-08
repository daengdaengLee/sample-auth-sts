package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeConfig 는 임시 디렉토리에 주어진 내용의 config.yaml 을 만들고 그 디렉토리 경로를
// 돌려준다. load 에 넘겨 파일 로딩을 검증한다.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(body), 0o600); err != nil {
		t.Fatalf("임시 config.yaml 작성 실패: %v", err)
	}
	return dir
}

// TestLoad_success 는 config.yaml 을 읽어 jwt 섹션 값을 그대로 돌려주는지 확인한다.
func TestLoad_success(t *testing.T) {
	dir := writeConfig(t, "jwt:\n  signing_secret: \"abc\"\n  ttl: \"3m\"\n")

	v, err := load(dir)
	if err != nil {
		t.Fatalf("load() 에러: %v", err)
	}
	if got, want := v.GetString("jwt.signing_secret"), "abc"; got != want {
		t.Errorf("jwt.signing_secret=%q, want %q", got, want)
	}
	if got, want := v.GetString("jwt.ttl"), "3m"; got != want {
		t.Errorf("jwt.ttl=%q, want %q", got, want)
	}
}

// TestLoad_missingFile 은 config.yaml 이 없으면 에러를 반환하는지 확인한다(부팅 시점 노출).
func TestLoad_missingFile(t *testing.T) {
	if _, err := load(t.TempDir()); err == nil {
		t.Fatal("설정 파일이 없는데 에러가 나지 않음")
	}
}

// TestLoad_envOverride 는 환경변수가 파일값을 덮어쓰는지 확인한다(점을 밑줄로 치환).
// 커밋된 샘플 시크릿을 배포에서 안전하게 대체하는 통로다.
func TestLoad_envOverride(t *testing.T) {
	dir := writeConfig(t, "jwt:\n  signing_secret: \"file-value\"\n")
	t.Setenv("JWT_SIGNING_SECRET", "env-value")

	v, err := load(dir)
	if err != nil {
		t.Fatalf("load() 에러: %v", err)
	}
	if got, want := v.GetString("jwt.signing_secret"), "env-value"; got != want {
		t.Errorf("환경변수 override 실패: jwt.signing_secret=%q, want %q", got, want)
	}
}
