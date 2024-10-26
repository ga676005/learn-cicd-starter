package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKeyEmpty(t *testing.T) {
	t.Parallel()
	h := http.Header{}

	_, err := GetAPIKey(h)
	if err != nil {
		if !errors.Is(err, ErrNoAuthHeaderIncluded) {
			t.Errorf("GetAPIKey error should be: %q, got: %q", ErrNoAuthHeaderIncluded, err)
		}
	} else {
		t.Errorf("Expect error but got none")
	}
}

func TestGetAPIKeyMalformed(t *testing.T) {
	t.Parallel()
	h := http.Header{}
	h.Set("Authorization", "123")

	_, err := GetAPIKey(h)
	if err != nil {
		if !errors.Is(err, ErrMalformedAuthorizationHeader) {
			t.Errorf("Expected error: %q, got: %q", ErrMalformedAuthorizationHeader, err)
		}
	} else {
		t.Error("Expected error but got none")
	}
}

func TestGetAPIKeyNoAPIKey(t *testing.T) {
	t.Parallel()
	h := http.Header{}
	h.Set("Authorization", "ApiKey")

	_, err := GetAPIKey(h)
	if err != nil {
		if !errors.Is(err, ErrMalformedAuthorizationHeader) {
			t.Errorf("Expected error: %q, got: %q", ErrMalformedAuthorizationHeader, err)
		}
	} else {
		t.Errorf("Expected error but got none")
	}

}

func TestGetAPIKeyOk(t *testing.T) {
	t.Parallel()
	h := http.Header{}
	h.Set("Authorization", "ApiKey 123")

	apiKey, err := GetAPIKey(h)
	if err != nil {
		t.Errorf("Unexpected error: %q", err)
		return
	}

	expectedAPIKey := "123"
	if apiKey != expectedAPIKey {
		t.Errorf("Expected API key: %q, got: %q", expectedAPIKey, apiKey)
	}
}

func TestGetAPIKeyTableDriven(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		authHeader     string
		expectedOutput string
		expectedError  error
	}{
		{
			name:           "ok",
			authHeader:     "ApiKey 123",
			expectedOutput: "123",
			expectedError:  nil,
		}, {
			name:           "empty",
			authHeader:     "",
			expectedOutput: "",
			expectedError:  ErrNoAuthHeaderIncluded,
		}, {
			name:           "malformed 1",
			authHeader:     "ApiKey",
			expectedOutput: "",
			expectedError:  errors.New("force fail"),
		}, {
			name:           "malformed 2",
			authHeader:     "123",
			expectedOutput: "",
			expectedError:  ErrMalformedAuthorizationHeader,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(tt *testing.T) {
			tt.Parallel()
			header := http.Header{}
			header.Set("Authorization", testCase.authHeader)
			output, err := GetAPIKey(header)
			if testCase.expectedError != nil {
				if !errors.Is(err, testCase.expectedError) {
					tt.Errorf(
						"error should be %q, but got %q",
						testCase.expectedError,
						err,
					)
				}

				if output != "" {
					tt.Errorf("expected empty output when error occurs, got %q", output)
				}
				return
			}

			if output != testCase.expectedOutput {
				tt.Errorf("output should be %q but got %q", testCase.expectedOutput, output)
			}
		})
	}
}
