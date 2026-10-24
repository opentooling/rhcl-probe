package probe

import (
	"encoding/xml"
	"fmt"
)

type junitSuites struct {
	XMLName  xml.Name     `xml:"testsuites"`
	Name     string       `xml:"name,attr"`
	Tests    int          `xml:"tests,attr"`
	Failures int          `xml:"failures,attr"`
	Skipped  int          `xml:"skipped,attr"`
	Time     string       `xml:"time,attr"`
	Suites   []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Skipped  int         `xml:"skipped,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *junitMessage `xml:"failure,omitempty"`
	Skipped   *junitMessage `xml:"skipped,omitempty"`
	Output    string        `xml:"system-out,omitempty"`
}

type junitMessage struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

// JUnit renders a report as JUnit XML, one test suite per group.
func JUnit(r Report) ([]byte, error) {
	out := junitSuites{Name: "rhcl-probe", Tests: len(r.Results), Failures: r.Failed, Skipped: r.Skipped,
		Time: seconds(r.DurationMs)}
	index := map[string]int{}
	for _, res := range r.Results {
		i, ok := index[res.Group]
		if !ok {
			i = len(out.Suites)
			index[res.Group] = i
			out.Suites = append(out.Suites, junitSuite{Name: res.Group})
		}
		s := &out.Suites[i]
		c := junitCase{Name: res.Name, Classname: "rhcl-probe." + res.ID, Time: seconds(res.DurationMs), Output: res.Detail}
		switch res.Status {
		case Fail:
			c.Failure = &junitMessage{Message: res.Detail, Text: res.Hint}
			s.Failures++
		case Skip:
			c.Skipped = &junitMessage{Message: res.Detail}
			s.Skipped++
		}
		s.Tests++
		s.Cases = append(s.Cases, c)
	}
	b, err := xml.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), b...), nil
}

func seconds(ms int64) string { return fmt.Sprintf("%.3f", float64(ms)/1000) }
