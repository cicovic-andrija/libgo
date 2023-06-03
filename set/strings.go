package set

type Strings map[string]void

func NewStringSet() Strings {
	return make(map[string]void)
}

func (s Strings) Insert(str string) {
	s[str] = void{}
}

func (s Strings) Delete(str string) {
	delete(s, str)
}

func (s Strings) Contains(str string) bool {
	_, found := s[str]
	return found
}
