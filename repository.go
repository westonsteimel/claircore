package claircore

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
)

// Repository is a package repository
type Repository struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Key  string `json:"key"`
	URI  string `json:"uri"`
}

func (a Repository) Value() (driver.Value, error) {
	return json.Marshal(a)
}

func (a *Repository) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}

	return json.Unmarshal(b, &a)
}
