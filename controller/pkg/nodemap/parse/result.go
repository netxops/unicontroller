package parse

import (
	"github.com/influxdata/telegraf/controller/pkg/nodemap/errors"
)

type ParseResult struct {
	Data   interface{}
	Errors []*errors.StructuredError
}

func NewParseResult() *ParseResult {
	return &ParseResult{
		Errors: make([]*errors.StructuredError, 0),
	}
}

func (pr *ParseResult) AddError(err *errors.StructuredError) {
	pr.Errors = append(pr.Errors, err)
}

func (pr *ParseResult) HasErrors() bool {
	return len(pr.Errors) > 0
}

func (pr *ParseResult) HasCriticalErrors() bool {
	for _, err := range pr.Errors {
		if err.Severity >= errors.SeverityError {
			return true
		}
	}
	return false
}
