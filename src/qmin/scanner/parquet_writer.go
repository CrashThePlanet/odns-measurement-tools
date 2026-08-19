package qmin_scanner

import (
	"bufio"
	"encoding/gob"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/parquet-go/parquet-go"
)

func WriteOutputParquet(tempPath string, outPath string) {
	tempFile, err := os.Open(tempPath)
	if err != nil {
		log.Fatalln("Could not read temporary file: {}", err.Error())
	}

	defer tempFile.Close()

	bufReader := bufio.NewReaderSize(tempFile, 1<<20)
	dec := gob.NewDecoder(bufReader)

	outFile, err := os.Create(outPath)
	if err != nil {
		log.Fatalln("could not create parquet output file: {}", err.Error())
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

	buf := make([]ParquetQueryResult, 0, Cfg.BatchSize/2)
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
		var record ParquetQueryResult
		decodeErr := dec.Decode(&record)
		if decodeErr != nil {
			if decodeErr == io.EOF {
				break
			}
			log.Fatalln("could not decode row: {}", decodeErr.Error())
		}
		buf = append(buf, record)
		if len(buf) >= Cfg.BatchSize/2 {
			if flushErr := flush(); flushErr != nil {
				log.Fatalln("could not flush batch to file: {}", err.Error())
			}
		}
	}
	if flushErr := flush(); flushErr != nil {
		log.Fatalln("could not flush batch to file: {}", err.Error())
	}
}
