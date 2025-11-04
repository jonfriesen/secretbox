package crypto

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsBoxedMessage(t *testing.T) {
	// First create a valid message using Dump
	nonce := [24]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}
	validMsg := &secretBoxedMessage{
		SchemaVersion: 1,
		Nonce:         nonce,
		Box:           []byte("test"),
	}
	validDumped := validMsg.Dump()

	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{
			name: "valid boxed message from Dump",
			data: validDumped,
			want: true,
		},
		{
			name: "invalid format - no brackets",
			data: []byte("not a boxed message"),
			want: false,
		},
		{
			name: "invalid format - missing EV prefix",
			data: []byte("[1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:dGVzdA==]"),
			want: false,
		},
		{
			name: "empty data",
			data: []byte(""),
			want: false,
		},
		{
			name: "partial format",
			data: []byte("EV[1:"),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsBoxedMessage(tt.data)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestSecretBoxedMessage_DumpAndLoad(t *testing.T) {
	t.Run("dump and load round trip", func(t *testing.T) {
		// Create a test message
		nonce := [24]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}
		box := []byte("test encrypted data")

		original := &secretBoxedMessage{
			SchemaVersion: 1,
			Nonce:         nonce,
			Box:           box,
		}

		// Dump to bytes
		dumped := original.Dump()
		require.NotEmpty(t, dumped)
		require.True(t, IsBoxedMessage(dumped), "dumped message should be recognized as boxed")

		// Load back
		loaded := &secretBoxedMessage{}
		err := loaded.Load(dumped)
		require.NoError(t, err)

		// Verify all fields match
		require.Equal(t, original.SchemaVersion, loaded.SchemaVersion)
		require.Equal(t, original.Nonce, loaded.Nonce)
		require.Equal(t, original.Box, loaded.Box)
	})
}

func TestSecretBoxedMessage_Load_InvalidFormats(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "invalid format - not boxed",
			data:    []byte("not a valid message"),
			wantErr: true,
		},
		{
			name:    "invalid base64 nonce",
			data:    []byte("EV[1:invalid_base64!:dGVzdA==]"),
			wantErr: true,
		},
		{
			name:    "invalid base64 box",
			data:    []byte("EV[1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:invalid_base64!]"),
			wantErr: true,
		},
		{
			name:    "nonce too short",
			data:    []byte("EV[1:dGVzdA==:dGVzdA==]"),
			wantErr: true,
		},
		{
			name:    "invalid schema version",
			data:    []byte("EV[abc:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:dGVzdA==]"),
			wantErr: true,
		},
		{
			name:    "empty data",
			data:    []byte(""),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sb := &secretBoxedMessage{}
			err := sb.Load(tt.data)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSecretBoxedMessage_Dump_Format(t *testing.T) {
	t.Run("verify dump format structure", func(t *testing.T) {
		nonce := [24]byte{}
		for i := range nonce {
			nonce[i] = byte(i)
		}
		box := []byte("encrypted content")

		sb := &secretBoxedMessage{
			SchemaVersion: 1,
			Nonce:         nonce,
			Box:           box,
		}

		dumped := sb.Dump()
		str := string(dumped)

		// Verify format: EV[version:nonce:box]
		require.Contains(t, str, "EV[")
		require.Contains(t, str, "]")
		require.Contains(t, str, "1:")

		// Verify nonce is properly base64 encoded
		nonceB64 := base64.StdEncoding.EncodeToString(nonce[:])
		require.Contains(t, str, nonceB64)

		// Verify box is properly base64 encoded
		boxB64 := base64.StdEncoding.EncodeToString(box)
		require.Contains(t, str, boxB64)
	})
}

func TestSecretBoxedMessage_SchemaVersions(t *testing.T) {
	t.Run("different schema versions", func(t *testing.T) {
		nonce := [24]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}
		box := []byte("test")

		// Test with schema version 1
		sb1 := &secretBoxedMessage{
			SchemaVersion: 1,
			Nonce:         nonce,
			Box:           box,
		}
		dumped1 := sb1.Dump()

		loaded1 := &secretBoxedMessage{}
		err := loaded1.Load(dumped1)
		require.NoError(t, err)
		require.Equal(t, 1, loaded1.SchemaVersion)
	})
}
