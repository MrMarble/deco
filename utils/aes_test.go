package utils

import "testing"

func TestGenAESKey(t *testing.T) {
	got := GenerateAESKey()

	if len(got.Key) != 16 {
		t.Errorf("Expected length of 16; got %d", len(got.Key))
	}
	if len(got.Key) != 16 {
		t.Errorf("Expected length of 16; got %d", len(got.Iv))
	}

	if string(got.Iv) == string(got.Key) {
		t.Errorf("Expected number to be random")
	}
}
