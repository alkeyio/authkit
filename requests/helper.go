package requests

func isRequired(defaultValue bool, required ...bool) bool {
	if len(required) > 0 {
		return required[0]
	}

	return defaultValue
}
