package httpapi

import (
	"errors"
	"net/http"

	"github.com/go-tangra/go-tangra/v4/listquery"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// The browser list endpoints answer the list contract (go-tangra
// specs/032-server-side-tables, contracts/http-list.md): page, page_size,
// sort and order in, {items,total,page,page_size,sort,order} out. A request
// with only the old cursor / limit parameters keeps the old shape
// ({items,next_cursor}) plus total for one release; mixing both styles is
// validation_failed on "cursor". Every total counts only what the caller may
// read: the visibility constraint is part of the count query.

// serveList answers one list request: legacy runs the old cursor path and
// returns its body plus the total, paged the list-contract page (also used,
// with one row, to count for legacy). mapErr maps a service error.
func serveList[T any](s *Server, w http.ResponseWriter, r *http.Request, spec listquery.Spec, mapErr func(error) error,
	legacy func() (map[string]any, error), paged func(listquery.Request) (listquery.Page[T], error)) {
	q := r.URL.Query()
	if legacy != nil && listquery.Legacy(q) {
		body, err := legacy()
		if err != nil {
			s.fail(w, r, mapErr(err))
			return
		}
		count, err := paged(store.ListRequest(listquery.Request{PageSize: 1}, spec))
		if err != nil {
			s.fail(w, r, mapErr(err))
			return
		}
		body["total"] = count.Total
		WriteJSON(w, http.StatusOK, body)
		return
	}
	req, err := listquery.Parse(q, spec)
	if err != nil {
		listParamError(w, err)
		return
	}
	pg, err := paged(req)
	if err != nil {
		s.fail(w, r, mapErr(err))
		return
	}
	WriteJSON(w, http.StatusOK, pg)
}

// listParamError answers an invalid list parameter: 422 naming the parameter
// only (never its value).
func listParamError(w http.ResponseWriter, err error) {
	param := "page"
	var le *listquery.Error
	if errors.As(err, &le) {
		param = le.Param
	}
	WriteDetail(w, ErrValidation, map[string]any{"param": param})
}
