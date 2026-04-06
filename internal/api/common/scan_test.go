package common

import (
	"reflect"
	"testing"
)

func TestEnsureSlice(t *testing.T) {
	t.Run("nil slices return empty non-nil slice", func(t *testing.T) {
		tests := []struct {
			name string
			call func() interface{}
		}{
			{"string", func() interface{} { var s []string; return EnsureSlice(s) }},
			{"int", func() interface{} { var s []int; return EnsureSlice(s) }},
			{"struct", func() interface{} {
				type item struct{ ID int }
				var s []item
				return EnsureSlice(s)
			}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := tt.call()
				rv := reflect.ValueOf(result)
				if rv.IsNil() {
					t.Errorf("EnsureSlice(nil) returned nil, expected empty slice")
				}
				if rv.Len() != 0 {
					t.Errorf("EnsureSlice(nil) returned slice with length %d, expected 0", rv.Len())
				}
			})
		}
	})

	t.Run("non-nil slice returned unchanged", func(t *testing.T) {
		input := []string{"a", "b", "c"}
		result := EnsureSlice(input)
		if !reflect.DeepEqual(result, input) {
			t.Errorf("EnsureSlice() = %v, want %v", result, input)
		}
	})

	t.Run("empty non-nil slice returned unchanged", func(t *testing.T) {
		input := []int{}
		result := EnsureSlice(input)
		if !reflect.DeepEqual(result, input) {
			t.Errorf("EnsureSlice() = %v, want %v", result, input)
		}
	})

	t.Run("single element slice returned unchanged", func(t *testing.T) {
		input := []int{42}
		result := EnsureSlice(input)
		if !reflect.DeepEqual(result, input) {
			t.Errorf("EnsureSlice() = %v, want %v", result, input)
		}
	})
}
