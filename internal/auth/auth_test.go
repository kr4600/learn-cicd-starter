package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
		shouldError   bool
	}{
		{
			name: "valid authorization header",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key-12345"},
			},
			expectedKey:   "my-secret-key-12345",
			expectedError: nil,
			shouldError:   false,
		},
		{
			name:          "missing authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
			shouldError:   true,
		},
		{
			name: "empty authorization header value",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
			shouldError:   true,
		},
		{
			name: "malformed header - missing ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"my-secret-key-12345"},
			},
			expectedKey: "",
			shouldError: true,
		},
		{
			name: "malformed header - wrong prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer my-secret-key-12345"},
			},
			expectedKey: "",
			shouldError: true,
		},
		{
			name: "malformed header - only ApiKey without key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey: "",
			shouldError: true,
		},
		{
			name: "malformed header - lowercase apikey",
			headers: http.Header{
				"Authorization": []string{"apikey my-secret-key-12345"},
			},
			expectedKey: "",
			shouldError: true,
		},
		{
			name: "valid header with extra spaces",
			headers: http.Header{
				"Authorization": []string{"ApiKey  my-secret-key-12345"},
			},
			expectedKey: "",
			expectedError: nil,
			shouldError: false,
		},
		{
			name: "valid header with key containing spaces",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-key with spaces"},
			},
			expectedKey: "my-key",
			expectedError: nil,
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tt.headers)

			if tt.shouldError {
				if err == nil {
					t.Errorf("expected an error but got none")
				}
				if tt.expectedError != nil && err != tt.expectedError {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}

			if apiKey != tt.expectedKey {
				t.Errorf("expected API key %q, got %q", tt.expectedKey, apiKey)
			}
		})
	}
}

func TestGetAPIKey_ErrorMessages(t *testing.T) {
	tests := []struct {
		name         string
		headers      http.Header
		errorMessage string
	}{
		{
			name:         "no auth header returns correct error",
			headers:      http.Header{},
			errorMessage: "no authorization header included",
		},
		{
			name: "malformed header returns correct error",
			headers: http.Header{
				"Authorization": []string{"Bearer token"},
			},
			errorMessage: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetAPIKey(tt.headers)
			if err == nil {
				t.Fatal("expected error but got none")
			}
			if err.Error() != tt.errorMessage {
				t.Errorf("expected error message %q, got %q", tt.errorMessage, err.Error())
			}
		})
	}
}

