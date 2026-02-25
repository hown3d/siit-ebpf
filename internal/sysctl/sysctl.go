package sysctl

import (
	"errors"
	"fmt"
	"strings"

	"github.com/lorenzosaino/go-sysctl"
)

type Sysctl struct {
	Name      []string
	Val       string
	IgnoreErr bool
}

func ApplySettings(sysctls []Sysctl) error {
	var errs error
	for _, s := range sysctls {
		key := strings.Join(s.Name, ".")
		err := sysctl.Set(key, s.Val)
		if err != nil && !s.IgnoreErr {
			errs = errors.Join(errs, fmt.Errorf("applying sysctl %s: %w", key, err))
		}
	}
	return errs
}
