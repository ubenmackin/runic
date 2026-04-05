package common

import "github.com/gorilla/mux"

// RouteRegistrar allows a resource package to register its own routes.
type RouteRegistrar interface {
	RegisterRoutes(r *mux.Router)
}
