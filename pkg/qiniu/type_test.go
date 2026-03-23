package qiniu

import "testing"

func TestRequestErrorIsMissingCNAME(t *testing.T) {
	err := &RequestError{
		StatusCode: 400,
		Code:       400392,
		Message:    "cname为空",
	}

	if !err.IsMissingCNAME() {
		t.Fatalf("expected error to be recognized as missing cname")
	}
}
