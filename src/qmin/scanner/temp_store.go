package qmin_scanner

import (
	"bufio"
	"encoding/gob"
	"fmt"
	"os"
)

type TempStore struct {
	file      *os.File
	bufWriter *bufio.Writer
	enc       *gob.Encoder
}

func NewTempStore() (*TempStore, error) {
	f, err := os.CreateTemp("", "scan-results.gob")
	if err != nil {
		return nil, fmt.Errorf("could not create temp file: {}", err)
	}

	bufWriter := bufio.NewWriterSize(f, 1<<20)
	return &TempStore{
		file:      f,
		bufWriter: bufWriter,
		enc:       gob.NewEncoder(bufWriter),
	}, nil
}

func (t *TempStore) WriteSingle(data ParquetQueryResult) error {
	if err := t.enc.Encode(&data); err != nil {
		return fmt.Errorf("could not encode record: {}", err)
	}
	return nil
}

func (t *TempStore) WriteBatch(batch []ParquetQueryResult) error {
	for i := range batch {
		if err := t.enc.Encode(&batch[i]); err != nil {
			return fmt.Errorf("could not encode record: {}", err)
		}
	}
	return nil
}

func (t *TempStore) Close() error {
	if err := t.bufWriter.Flush(); err != nil {
		t.file.Close()
		return fmt.Errorf("could not flush buffer to temp file: %w", err)
	}
	return t.file.Close()
}

func (t *TempStore) Path() string {
	return t.file.Name()
}

func (t *TempStore) Delete() error {
	return os.Remove(t.file.Name())
}
