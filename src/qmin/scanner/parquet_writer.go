package qmin_scanner

import (
	"bufio"
	"encoding/gob"
	"fmt"
	"io"
	"os"

	"github.com/parquet-go/parquet-go"
)

func WriteOutputParquet(tempPath string, outPath string) error {
	tempFile, err := os.Open(tempPath)
	if err != nil {
		return fmt.Errorf("could not read temporary file: %w", err)
	}

	defer tempFile.Close()

	bufReader := bufio.NewReaderSize(tempFile, 1<<20)
	dec := gob.NewDecoder(bufReader)

	outFile, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("could not create parquet output file: %w", err)
	}

	defer func() {
		if closeErr := outFile.Close(); err == nil {
			err = closeErr
		}
	}()

	writer := parquet.NewGenericWriter[ParquetQueryResult](outFile)
	defer func() {
		if closeErr := writer.Close(); err == nil {
			err = closeErr
		}
	}()

	batchSize := 100
	buf := make([]ParquetQueryResult, 0, batchSize)

	flush := func() error {
		if len(buf) == 0 {
			return nil
		}

		if _, writeErr := writer.Write(buf); writeErr != nil {
			return fmt.Errorf("could not write row to parquet file: {}", writeErr.Error())
		}
		buf = buf[:0]
		return nil
	}

	for {
		buf = append(buf, ParquetQueryResult{})

		if decodeErr := dec.Decode(&buf[len(buf)-1]); decodeErr != nil {
			if decodeErr == io.EOF {
				buf = buf[:len(buf)-1]
				break
			}
			return fmt.Errorf("could not decode row: %w", decodeErr)
		}

		if len(buf) >= batchSize {
			if flushErr := flush(); flushErr != nil {
				return flushErr
			}
		}

	}
	if flushErr := flush(); flushErr != nil {
		return flushErr
	}

	return err
}
