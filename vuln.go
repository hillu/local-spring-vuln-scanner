package main

import (
	"fmt"
	"strings"
)

type Vulnerabilities uint8

func (v Vulnerabilities) String() string {
	var tags []string
	if v&CVE_2022_22965 != 0 {
		tags = append(tags, "CVE-2022-22965")
	}
	return strings.Join(tags, ", ")
}

func (v *Vulnerabilities) Set(s string) error {
	*v = 0
	for _, tag := range strings.Split(s, ",") {
		switch strings.ToLower(strings.Trim(tag, " ")) {
		case "cve-2022-22965", "spring4shell", "springshell":
			*v |= CVE_2022_22965
		case "":
		default:
			return fmt.Errorf("invalid vulnerability '%s'", tag)
		}
	}
	return nil
}

const (
	CVE_2022_22965 = 1 << iota
)

const (
	CheckDefaultVulnerabilities Vulnerabilities = CVE_2022_22965
	CheckAllVulnerabilities     Vulnerabilities = 0xff
)
