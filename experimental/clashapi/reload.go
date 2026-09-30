//go:build !ios

package clashapi

import (
	"net/http"

	"github.com/go-chi/render"
)

func reload(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if checker := server.configChecker(); checker != nil {
			if err := checker.CheckConfig(); err != nil {
				server.logger.Error("rejecting config reload: ", err)
				render.Status(r, http.StatusBadRequest)
				render.JSON(w, r, newError(err.Error()))
				return
			}
		}
		defer func() {
			server.logger.Warn("sing-box restarting...")
			server.router.Reload()
		}()
		render.NoContent(w, r)
	}
}
