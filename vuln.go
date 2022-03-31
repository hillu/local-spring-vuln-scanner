package main

import (
	"fmt"
	"strings"
)

type Vulnerabilities uint8

func (v Vulnerabilities) String() string {
	var tags []string
	if v&CVE_spring4shell != 0 {
		tags = append(tags, "spring4shell")
	}
	return strings.Join(tags, ", ")
}

func (v *Vulnerabilities) Set(s string) error {
	*v = 0
	for _, tag := range strings.Split(s, ",") {
		switch strings.Trim(tag, " ") {
		case "spring4shell":
			*v |= CVE_spring4shell
		case "":
		default:
			return fmt.Errorf("invalid vulnerability '%s'", tag)
		}
	}
	return nil
}

const (
	CVE_spring4shell = 1 << iota
)

const (
	CheckDefaultVulnerabilities Vulnerabilities = CVE_spring4shell
	CheckAllVulnerabilities     Vulnerabilities = 0xff
)
