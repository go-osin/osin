package osin

import (
	"net/http"
	"time"
)

// InfoRequest is a request for information about some AccessData
type InfoRequest struct {
	Code       string      // Code to look up
	AccessData *AccessData // AccessData associated with Code
}

// InfoOutput allows processing the Response object before finishing
type InfoOutput interface {
	ProcessInfoOutput(w *Response, r *http.Request, ir *InfoRequest)
}

// HandleInfoRequest is an http.HandlerFunc for server information
// NOT an RFC specification.
func (s *Server) HandleInfoRequest(w *Response, r *http.Request) *InfoRequest {
	r.ParseForm()

	// generate info request
	ret := &InfoRequest{
		Code: r.Form.Get("code"),
	}

	if ret.Code == "" {
		w.SetError(E_INVALID_REQUEST, "")
		return nil
	}

	var err error

	// load access data
	ret.AccessData, err = s.Storage.LoadAccess(ret.Code)
	if err != nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = err
		return nil
	}
	if ret.AccessData.Client == nil {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.AccessData.Client.RedirectUri == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.AccessData.IsExpired() {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	return ret
}

// FinishInfoRequest finalizes the request handled by HandleInfoRequest
func (s *Server) FinishInfoRequest(w *Response, r *http.Request, ir *InfoRequest) {
	// don't process if is already an error
	if w.IsError {
		return
	}

	// output data
	w.Output["client_id"] = ir.AccessData.Client.Id
	w.Output["access_token"] = ir.AccessData.AccessToken
	w.Output["token_type"] = s.Config.TokenType
	w.Output["expires_in"] = ir.AccessData.CreatedAt.Add(time.Duration(ir.AccessData.ExpiresIn)*time.Second).Sub(time.Now()) / time.Second
	if ir.AccessData.RefreshToken != "" {
		w.Output["refresh_token"] = ir.AccessData.RefreshToken
	}
	if ir.AccessData.Scope != "" {
		w.Output["scope"] = ir.AccessData.Scope
	}

	if s.InfoOutput != nil {
		s.InfoOutput.ProcessInfoOutput(w, r, ir)
	}
}
