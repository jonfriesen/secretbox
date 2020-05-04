package crypto

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strconv"
)

var messageParser = regexp.MustCompile("\\AEV\\[(\\d):([A-Za-z0-9+=/]{32}):(.+)\\]\\z")

// ErrInvalidMessageFormat is an error that occurs when boxes are not formatted correctly
var ErrInvalidMessageFormat = errors.New("invalid message format")

type secretBoxedMessage struct {
	SchemaVersion int
	Nonce         [24]byte
	Box           []byte
}

// IsBoxedMessage returns true if the byte slice passed in is a valid box
func IsBoxedMessage(data []byte) bool {
	return messageParser.Find(data) != nil
}

// Dump puts the secret box in persistable format
func (s *secretBoxedMessage) Dump() []byte {
	nonce := base64.StdEncoding.EncodeToString(s.Nonce[:])
	box := base64.StdEncoding.EncodeToString(s.Box)

	str := fmt.Sprintf("EV[%d:%s:%s]", s.SchemaVersion, nonce, box)
	return []byte(str)
}

// Load marshals a persisted box to the struct
func (s *secretBoxedMessage) Load(from []byte) error {
	var sSchemaVer, sNonce, sBox string
	var err error

	allMatches := messageParser.FindAllStringSubmatch(string(from), -1)
	if len(allMatches) != 1 {
		return ErrInvalidMessageFormat
	}

	matches := allMatches[0]
	if len(matches) != 4 {
		return ErrInvalidMessageFormat
	}

	sSchemaVer = matches[1]
	sNonce = matches[2]
	sBox = matches[3]

	// get and set schema version
	s.SchemaVersion, err = strconv.Atoi(sSchemaVer)
	if err != nil {
		return err
	}

	// decode nonce
	nonceSlice, err := base64.StdEncoding.DecodeString(sNonce)
	if err != nil {
		return err
	}
	if len(nonceSlice) != 24 {
		return fmt.Errorf("nonce is too short")
	}

	var nonce [24]byte
	copy(nonce[:], nonceSlice[0:24])
	s.Nonce = nonce

	// decode secretbox
	box, err := base64.StdEncoding.DecodeString(sBox)
	if err != nil {
		return err
	}
	s.Box = box

	return nil
}
