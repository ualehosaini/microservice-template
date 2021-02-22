package data

import (
	"encoding/json"
	"io"
)

// FromJSON deserializes the interface from JSON string
func FromJSON(i interface{}, reader io.Reader) error {
	decoder := json.NewDecoder(reader)
	return decoder.Decode(i)
}

// ToJSON serializes interface into a json String
func ToJSON(i interface{}, writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	return encoder.Encode(i)
}
