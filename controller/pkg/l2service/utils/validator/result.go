package validator

import "strings"

type Result interface {
	Status() bool
	Msg() string
	AddError(Result)
}

type validateResult struct {
	status bool
	msg    string
	errors []Result
}

func NewValidateResult(status bool, msg string) Result {
	return &validateResult{
		status: status,
		msg:    msg,
		errors: []Result{},
	}
}

func (r *validateResult) Status() bool {
	return r.status
}

func (r *validateResult) Msg() string {
	if len(r.errors) == 0 {
		if r.status == true {
			return ""
		} else {
			return r.msg
		}
	}
	m := []string{}
	for _, e := range r.errors {
		m = append(m, e.Msg())
	}

	return strings.Join(m, "\n")

}

func (r *validateResult) AddError(result Result) {
	r.errors = append(r.errors, result)

	if r.Status() == true {
		r.status = false
	}
}
