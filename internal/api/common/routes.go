package common

import "github.com/gorilla/mux"

type RouteRegistrar interface {
	RegisterRoutes(r *mux.Router)
}
