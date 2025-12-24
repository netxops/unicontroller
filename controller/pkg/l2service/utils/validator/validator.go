package validator

type Validator interface {
	Validate(data map[string]interface{}) Result
}

type ValidateChain struct {
	Chain       []Validator
	stopOnError bool
}

func NewValidateChain() *ValidateChain {
	return &ValidateChain{
		Chain:       []Validator{},
		stopOnError: true,
	}
}

func (vc *ValidateChain) Add(validator Validator) {
	vc.Chain = append(vc.Chain, validator)
}

func (vc *ValidateChain) StopOnError() *ValidateChain {
	vc.stopOnError = true
	return vc
}

func (vc *ValidateChain) Validate(data map[string]interface{}) Result {
	errors := []Result{}
	for _, v := range vc.Chain {
		result := v.Validate(data)
		if result.Status() == false {
			if vc.stopOnError == true {
				return result
			} else {
				errors = append(errors, result)
			}
		}
	}

	if len(errors) == 0 {
		return NewValidateResult(true, "")
	} else {
		result := NewValidateResult(false, "")
		for _, e := range errors {
			result.AddError(e)
		}

		return result

	}
}
