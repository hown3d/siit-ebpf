package testutil

import (
	"os"
)

const kernelTraceFile = "/sys/kernel/tracing/trace"

type kernelTraces struct {
	f *os.File
}

func KernelTraceReader() (*kernelTraces, error) {
	f, err := os.OpenFile(kernelTraceFile, os.O_RDONLY, 0o640)
	if err != nil {
		return nil, err
	}
	return &kernelTraces{
		f: f,
	}, nil
}

func (k kernelTraces) Read(b []byte) (n int, err error) {
	return k.f.Read(b)
}

func (k kernelTraces) Clear() error {
	// i dont know why but it only works if the file is opened as a new fd
	return os.WriteFile(kernelTraceFile, []byte{}, 0o640)
}

func (k kernelTraces) Close() error {
	return k.f.Close()
}
