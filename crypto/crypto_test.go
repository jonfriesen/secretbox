package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKey_Generate(t *testing.T) {
	t.Run("test generation", func(t *testing.T) {
		k1, k2 := Key{}, Key{}

		err := k1.Generate()
		require.NoError(t, err)

		err = k2.Generate()
		require.NoError(t, err)

		require.NotEqual(t, k1, k2, "generated keys should be different")
		require.NotEqual(t, Key{}, k1, "generated key should not be empty")
		require.NotEqual(t, Key{}, k2, "generated key should not be empty")
	})
}

func Test_generateNonce(t *testing.T) {
	t.Run("test nonce generation", func(t *testing.T) {
		n1, err := generateNonce()
		require.NoError(t, err)
		n2, err := generateNonce()
		require.NoError(t, err)

		require.NotEqual(t, n1, n2, "nonces should be different")
		require.NotEqual(t, [24]byte{}, n1, "nonce should not be empty")
		require.NotEqual(t, [24]byte{}, n2, "nonce should not be empty")
	})
}

func TestKey_RoundTrip(t *testing.T) {
	type args struct {
		message []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "simple happy path",
			args: args{
				message: []byte("hello, world!"),
			},
		},
		{
			name: "empty message",
			args: args{
				message: []byte{},
			},
		},
		{
			name: "large message",
			args: args{
				message: make([]byte, 10000),
			},
		},
		{
			name: "unicode message",
			args: args{
				message: []byte("Hello 世界! 🔐 Encryption"),
			},
		},
		{
			name: "binary data",
			args: args{
				message: []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := Key{}
			err := key.Generate()
			require.NoError(t, err)

			ciphertext, err := key.Encrypt(tt.args.message)
			require.NoError(t, err)
			require.NotEqual(t, tt.args.message, ciphertext, "ciphertext should differ from plaintext")

			plaintext, err := key.Decrypt(ciphertext)
			require.NoError(t, err)

			// For empty messages, both nil and []byte{} are valid
			if len(tt.args.message) == 0 {
				require.Empty(t, plaintext)
			} else {
				require.Equal(t, tt.args.message, plaintext)
			}
		})
	}
}

func TestKey_String(t *testing.T) {
	t.Run("string representation", func(t *testing.T) {
		key := Key{}
		err := key.Generate()
		require.NoError(t, err)

		str := key.String()
		require.NotEmpty(t, str)
		require.Equal(t, 64, len(str), "hex string should be 64 chars (32 bytes * 2)")
	})
}

func TestKey_Bytes(t *testing.T) {
	t.Run("bytes conversion", func(t *testing.T) {
		key := Key{}
		err := key.Generate()
		require.NoError(t, err)

		bytes := key.Bytes()
		require.Equal(t, 32, len(bytes))
		require.NotEqual(t, [32]byte{}, bytes, "key bytes should not be empty")
	})
}

func TestKey_Encrypt_AlreadyEncrypted(t *testing.T) {
	t.Run("double encryption protection", func(t *testing.T) {
		key := Key{}
		err := key.Generate()
		require.NoError(t, err)

		message := []byte("test message")
		ciphertext1, err := key.Encrypt(message)
		require.NoError(t, err)

		// Encrypting already encrypted data should return same ciphertext
		ciphertext2, err := key.Encrypt(ciphertext1)
		require.NoError(t, err)
		require.Equal(t, ciphertext1, ciphertext2, "encrypting already encrypted data should return same data")
	})
}

func TestKey_Decrypt_InvalidKey(t *testing.T) {
	t.Run("decrypt with wrong key", func(t *testing.T) {
		key1 := Key{}
		err := key1.Generate()
		require.NoError(t, err)

		key2 := Key{}
		err = key2.Generate()
		require.NoError(t, err)

		message := []byte("secret message")
		ciphertext, err := key1.Encrypt(message)
		require.NoError(t, err)

		// Try to decrypt with wrong key
		_, err = key2.Decrypt(ciphertext)
		require.Error(t, err)
		require.Equal(t, ErrDecryption, err)
	})
}

func TestKey_Decrypt_CorruptedData(t *testing.T) {
	t.Run("decrypt corrupted ciphertext", func(t *testing.T) {
		key := Key{}
		err := key.Generate()
		require.NoError(t, err)

		message := []byte("test message")
		ciphertext, err := key.Encrypt(message)
		require.NoError(t, err)

		// Corrupt the ciphertext
		corrupted := make([]byte, len(ciphertext))
		copy(corrupted, ciphertext)
		corrupted[len(corrupted)/2] ^= 0xFF // Flip bits in middle

		_, err = key.Decrypt(corrupted)
		require.Error(t, err)
	})
}

func TestKey_Decrypt_InvalidFormat(t *testing.T) {
	t.Run("decrypt invalid format", func(t *testing.T) {
		key := Key{}
		err := key.Generate()
		require.NoError(t, err)

		invalidData := []byte("not a valid encrypted message")
		_, err = key.Decrypt(invalidData)
		require.Error(t, err)
	})
}
