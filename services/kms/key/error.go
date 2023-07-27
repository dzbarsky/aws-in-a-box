package key

type InvalidSigningAlgorithm struct{}

func (e InvalidSigningAlgorithm) Error() string {
	return "invalid signing algorithm"
}
