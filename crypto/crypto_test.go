package crypto

import (
	"reflect"
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

		require.NotSame(t, k1, k2)
	})
}

func Test_generateNonce(t *testing.T) {
	t.Run("test nonce generation", func(t *testing.T) {
		n1, err := generateNonce()
		require.NoError(t, err)
		n2, err := generateNonce()
		require.NoError(t, err)

		require.NotSame(t, n1, n2)
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := Key{}
			err := key.Generate()
			require.NoError(t, err)

			ciphertext, err := key.Encrypt(tt.args.message)
			require.NoError(t, err)

			plaintext, err := key.Decrypt(ciphertext)
			require.NoError(t, err)

			require.Equal(t, tt.args.message, plaintext)

		})
	}
}

func TestKey_encrypt(t *testing.T) {
	type args struct {
		message []byte
	}
	tests := []struct {
		name    string
		k       *Key
		args    args
		want    *secretBoxedMessage
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.k.encrypt(tt.args.message)
			if (err != nil) != tt.wantErr {
				t.Errorf("Key.encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Key.encrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}
