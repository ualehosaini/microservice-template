package handlers

import (
	"net/http"

	"github.com/Ubivius/microservice-template/pkg/data"
)

// UpdateProducts updates the product with the ID specified in the received JSON product
func (productHandler *ProductsHandler) UpdateProducts(responseWriter http.ResponseWriter, request *http.Request) {
	product := request.Context().Value(KeyProduct{}).(*data.Product)
	productHandler.logger.Println("Handle PUT product", product.ID)

	// Update product
	err := data.UpdateProduct(product)
	if err == data.ErrorProductNotFound {
		productHandler.logger.Println("[ERROR} product not found", err)
		http.Error(responseWriter, "Product not found", http.StatusNotFound)
		return
	}

	// Returns status, no content required
	responseWriter.WriteHeader(http.StatusNoContent)
}
