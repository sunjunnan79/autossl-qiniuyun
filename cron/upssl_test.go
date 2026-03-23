package cron

import (
	"reflect"
	"testing"
)

func TestFilterUnpublishedDomains(t *testing.T) {
	got := filterUnpublishedDomains(
		[]string{"a.example.com", "b.example.com", "c.example.com"},
		[]string{"a.example.com", "c.example.com"},
	)

	want := []string{"b.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestFilterUnpublishedDomainsKeepsOrderDeterministic(t *testing.T) {
	got := filterUnpublishedDomains(
		[]string{"c.example.com", "a.example.com", "b.example.com"},
		nil,
	)

	want := []string{"a.example.com", "b.example.com", "c.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}
