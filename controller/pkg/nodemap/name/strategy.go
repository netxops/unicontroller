package name

type FormatSelector int

const (
	_ FormatSelector = iota
	SIMPLE_NETWORK
	COMPLEX_NETWORK
	SIMPLE_SERVICE
	COMPLEX_SERVICE
	SIMPLE_POOL
	COMPLEX_POOL
	SIMPLE_VIP
	COMPLEX_VIP
	SIMPLE_POLICY
	COMPLEX_POLICY
)

func (fs FormatSelector) String() string {
	return []string{
		"SIMPLE_NETWORK", "COMPLEX_NETWORK", "SIMPLE_SERVICE", "COMPLEX_SERVICE",
		"SIMPLE_POOL", "COMPLEX_POOL", "SIMPLE_VIP", "COMPLEX_VIP", "SIMPLE_POLICY", "COMPLEX_POLICY",
	}[fs-1]
}

type NameStrategy struct {
	formatterMap map[FormatSelector]*Formatter
}

func NewNameStrategy() *NameStrategy {
	return &NameStrategy{}
}

func (ns *NameStrategy) WithFormatter(selector FormatSelector, format *Formatter) *NameStrategy {
	if ns.formatterMap == nil {
		ns.formatterMap = map[FormatSelector]*Formatter{}
	}
	ns.formatterMap[selector] = format

	return ns
}

func (ns *NameStrategy) Formatter(selector FormatSelector) *Formatter {
	f := ns.formatterMap[selector]
	if f == nil {
		panic(selector)
	}

	return f
}
