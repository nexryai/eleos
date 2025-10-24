package worker

func TestFunc() {
	for _, p := range products {
		_ = p.UUID()
	}
}
