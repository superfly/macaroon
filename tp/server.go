package tp

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/superfly/macaroon"
)

type flowData struct {
	ticket    []byte
	caveats   []macaroon.Caveat
	discharge *macaroon.Macaroon
	log       logrus.FieldLogger
}

type TP struct {
	Location string
	Key      macaroon.EncryptionKey
	Store    Store
	Log      logrus.FieldLogger
}

func (tp *TP) InitRequestMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var jr jsonInitRequest
		if err := json.NewDecoder(r.Body).Decode(&jr); err != nil {
			tp.getLog(r).WithError(err).Warn("read/parse request")
			http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
			return
		}

		fd, r := tp.newFDOrError(w, r, "init", jr.Ticket)
		if fd == nil {
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (tp *TP) HandlePollRequest(w http.ResponseWriter, r *http.Request) {
	store := tp.storeOrError(w, r)
	if store == nil {
		return
	}

	parts := strings.Split(r.URL.EscapedPath(), "/")
	last := parts[len(parts)-1]

	sd, err := store.GetByPollSecret(last)
	if err != nil || sd == nil {
		tp.getLog(r).WithError(err).Warn("store lookup by poll secret")
		http.Error(w, `{"error": "not found"}`, http.StatusNotFound)
		return
	}

	fd, r := tp.newFDOrError(w, r, "poll", sd.Ticket)
	if fd == nil {
		return
	}

	if sd.ResponseBody == nil || sd.ResponseStatus == 0 {
		tp.RespondError(w, r, http.StatusAccepted, "not ready")
		return
	}

	if err := store.DeleteByPollSecret(last); err != nil {
		tp.getLog(r).WithError(err).Warn("store delete")
		http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
		return
	}

	log := tp.getLog(r).WithFields(logrus.Fields{
		"status": sd.ResponseStatus,
		"resp":   "discharge",
	})

	w.WriteHeader(sd.ResponseStatus)
	if _, err := w.Write(sd.ResponseBody); err != nil {
		log.WithError(err).Warn("writing response")
		return
	}

	log.Info()
}

func (tp *TP) UserRequestMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		store := tp.storeOrError(w, r)
		if store == nil {
			return
		}

		userSecret, err := store.UserSecretFromRequest(r)
		if err != nil || userSecret == "" {
			tp.getLog(r).WithError(err).Warn("extracting user secret from request")
			http.Error(w, `{"error": "not found"}`, http.StatusNotFound)
			return
		}

		sd, err := store.GetByUserSecret(userSecret)
		if err != nil || sd == nil {
			tp.getLog(r).WithError(err).Warn("store lookup by poll secret")
			http.Error(w, `{"error": "not found"}`, http.StatusNotFound)
			return
		}

		fd, r := tp.newFDOrError(w, r, "poll", sd.Ticket)
		if fd == nil {
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (tp *TP) RespondError(w http.ResponseWriter, r *http.Request, statusCode int, msg string) {
	tp.respond(w, r, "error", statusCode, &jsonResponse{
		Error: msg,
	})
}

func (tp *TP) RespondDischarge(w http.ResponseWriter, r *http.Request, caveats ...macaroon.Caveat) {
	tp.respondDischarge(w, r, "immediate", caveats...)
}

func (tp *TP) respondDischarge(w http.ResponseWriter, r *http.Request, respType string, caveats ...macaroon.Caveat) {
	fd := tp.fdOrError(w, r)
	if fd == nil {
		return
	}

	if err := fd.discharge.Add(caveats...); err != nil {
		tp.getLog(r).WithError(err).Warn("attenuating discharge")
		http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
		return
	}

	tok, err := fd.discharge.String()
	if err != nil {
		tp.getLog(r).WithError(err).Warn("encode discharge")
		http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
		return
	}

	tp.respond(w, r, respType, http.StatusCreated, &jsonResponse{
		Discharge: tok,
	})
}

func (tp *TP) RespondPoll(w http.ResponseWriter, r *http.Request) string {
	var (
		fd    = tp.fdOrError(w, r)
		store = tp.storeOrError(w, r)
	)
	if fd == nil || store == nil {
		return ""
	}

	_, pollSecret, err := store.Put(&StoreData{Ticket: fd.ticket})
	if err != nil {
		tp.getLog(r).WithError(err).Warn("store put")
		http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
		return ""
	}

	tp.respond(w, r, "poll", http.StatusCreated, &jsonResponse{
		PollURL: tp.url("/poll/" + url.PathEscape(pollSecret)),
	})

	return pollSecret
}

func (tp *TP) DischargePoll(pollSecret string, caveats ...macaroon.Caveat) error {
	return tp.dischargePoller(pollSecret, "", caveats...)
}

func (tp *TP) AbortPoll(pollSecret string, message string) error {
	return tp.abortPoller(pollSecret, "", message)
}

func (tp *TP) RespondUserInteractive(w http.ResponseWriter, r *http.Request) string {
	var (
		fd    = tp.fdOrError(w, r)
		store = tp.storeOrError(w, r)
	)
	if fd == nil || store == nil {
		return ""
	}

	userSecret, pollSecret, err := store.Put(&StoreData{Ticket: fd.ticket})
	if err != nil {
		tp.getLog(r).WithError(err).Warn("store put")
		http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
		return ""
	}

	tp.respond(w, r, "user-interactive", http.StatusCreated, &jsonResponse{
		UserInteractive: &jsonUserInteractive{
			PollURL: tp.url("/poll/" + pollSecret),
			UserURL: store.UserSecretToURL(userSecret),
		},
	})

	return userSecret
}

func (tp *TP) DischargeUserInteractive(userSecret string, caveats ...macaroon.Caveat) error {
	return tp.dischargePoller("", userSecret, caveats...)
}

func (tp *TP) AbortUserInteractive(userSecret string, message string) error {
	return tp.abortPoller("", userSecret, message)
}

func (tp *TP) dischargePoller(pollSecret, userSecret string, caveats ...macaroon.Caveat) error {
	if tp.Store == nil {
		return errors.New("no store")
	}

	var (
		sd  *StoreData
		err error
	)
	if pollSecret != "" {
		sd, err = tp.Store.GetByPollSecret(pollSecret)
	} else {
		sd, err = tp.Store.GetByUserSecret(userSecret)
	}
	if err != nil {
		return err
	}

	fd, err := tp.newFD(nil, "background", sd.Ticket)
	if err != nil {
		return err
	}

	if err := fd.discharge.Add(caveats...); err != nil {
		return err
	}

	tok, err := fd.discharge.String()
	if err != nil {
		return err
	}

	jresp, err := json.Marshal(&jsonResponse{Discharge: tok})
	if err != nil {
		return err
	}

	sd.ResponseBody = jresp
	sd.ResponseStatus = http.StatusOK

	if _, _, err := tp.Store.Put(sd); err != nil {
		return err
	}

	return nil
}

func (tp *TP) abortPoller(pollSecret, userSecret string, message string) error {
	if tp.Store == nil {
		return errors.New("no store")
	}

	var (
		sd  *StoreData
		err error
	)
	if pollSecret != "" {
		sd, err = tp.Store.GetByPollSecret(pollSecret)
	} else {
		sd, err = tp.Store.GetByUserSecret(userSecret)
	}
	if err != nil {
		return err
	}

	jresp, err := json.Marshal(&jsonResponse{Error: message})
	if err != nil {
		return err
	}

	sd.ResponseBody = jresp
	sd.ResponseStatus = http.StatusOK

	if _, _, err := tp.Store.Put(sd); err != nil {
		return err
	}

	return nil
}

func (tp *TP) respond(w http.ResponseWriter, r *http.Request, respType string, statusCode int, jresp *jsonResponse) {
	log := tp.getLog(r).WithFields(logrus.Fields{
		"status": statusCode,
		"resp":   respType,
	})

	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(jresp); err != nil {
		log.WithError(err).Warn("writing response")
		return
	}

	log.Info()
}

type contextKey string

const contextKeyFlowData = contextKey("flow-data")

func CaveatsFromRequest(r *http.Request) ([]macaroon.Caveat, error) {
	if fd, ok := r.Context().Value(contextKeyFlowData).(*flowData); ok && fd != nil {
		return fd.caveats, nil
	}

	return nil, errors.New("middleware not called")
}

func (tp *TP) newFDOrError(w http.ResponseWriter, r *http.Request, reqType string, ticket []byte) (*flowData, *http.Request) {
	fd, err := tp.newFD(r, reqType, ticket)
	if err != nil {
		tp.getLog(r).WithError(err).Warn("recover ticket")
		http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
		return nil, r
	}

	ctx := context.WithValue(r.Context(), contextKeyFlowData, fd)
	return fd, r.WithContext(ctx)
}

func (tp *TP) newFD(r *http.Request, reqType string, ticket []byte) (*flowData, error) {
	log := tp.getLog(r).WithField("req", reqType)

	caveats, discharge, err := macaroon.DischargeTicket(tp.Key, tp.Location, ticket)
	if err != nil {
		return nil, err
	}

	fd := &flowData{
		ticket:    ticket,
		caveats:   caveats,
		discharge: discharge,
		log:       log.WithField("tid", digest(ticket)),
	}

	return fd, nil
}

func (tp *TP) fdOrError(w http.ResponseWriter, r *http.Request) *flowData {
	if fd, ok := r.Context().Value(contextKeyFlowData).(*flowData); ok && fd != nil {
		return fd
	}

	tp.getLog(r).Warn("middleware not called")
	http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
	return nil
}

func (tp *TP) storeOrError(w http.ResponseWriter, r *http.Request) Store {
	if tp.Store != nil {
		return tp.Store
	}

	tp.getLog(r).Warn("missing store")
	http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)

	return nil
}

func (tp *TP) getLog(r *http.Request) logrus.FieldLogger {
	if r != nil {
		if fd, ok := r.Context().Value(contextKeyFlowData).(*flowData); ok && fd.log != nil {
			return fd.log
		}
	}
	if tp.Log != nil {
		return tp.Log
	}

	log := logrus.New()
	log.SetOutput(io.Discard)
	return log
}

func (tp *TP) url(path string) string {
	if strings.HasSuffix(tp.Location, "/") {
		return tp.Location + InitPath[1:] + path
	}
	return tp.Location + InitPath + path
}

func randBytes(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}
