package data

import "testing"

func TestChecksValidation(t *testing.T) {
	product := &Product{
		Name:  "Malcolm",
		Price: 2.00,
		SKU:   "abs-abs-abscd",
	}

	err := product.ValidateProduct()

	if err != nil {
		t.Fatal(err)
	}
}
