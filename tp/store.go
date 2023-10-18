package tp

import (
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/crypto/blake2b"
)

type StoreData struct {
	Ticket         []byte
	ResponseStatus int
	ResponseBody   []byte
}

type Store interface {
	Put(*StoreData) (userSecret, pollSecret string, err error)
	Delete(*StoreData) error

	GetByPollSecret(string) (*StoreData, error)
	GetByUserSecret(string) (*StoreData, error)

	UserSecretMunger
}

type UserSecretMunger interface {
	UserSecretToURL(userSecret string) (url string)
	UserSecretFromRequest(r *http.Request) (string, error)
}

type MemoryStore struct {
	UserSecretMunger
	Cache *lru.Cache[string, *StoreData]

	_secret         []byte
	_initSecretOnce sync.Once
}

func NewMemoryStore(m UserSecretMunger, size int) (*MemoryStore, error) {
	cache, err := lru.New[string, *StoreData](size)
	if err != nil {
		return nil, err
	}

	return &MemoryStore{
		Cache:            cache,
		UserSecretMunger: PrefixMunger("/user/"),
	}, nil
}

var _ Store = (*MemoryStore)(nil)

var (
	errNotFound = errors.New("not found")
)

func (s *MemoryStore) Put(sd *StoreData) (userSecret, pollSecret string, err error) {
	userSecret, pollSecret = s.ticketSecrets(sd.Ticket)
	s.Cache.Add("u"+digest(userSecret), sd)
	s.Cache.Add("p"+digest(pollSecret), sd)
	return
}

func (s *MemoryStore) Delete(sd *StoreData) error {
	userSecret, pollSecret := s.ticketSecrets(sd.Ticket)
	s.Cache.Remove("u" + digest(userSecret))
	s.Cache.Remove("p" + digest(pollSecret))
	return nil
}

func (s *MemoryStore) GetByPollSecret(pollSecret string) (*StoreData, error) {
	if sd, ok := s.Cache.Get("p" + digest(pollSecret)); ok {
		return sd, nil
	}
	return nil, errNotFound
}

func (s *MemoryStore) GetByUserSecret(userSecret string) (*StoreData, error) {
	if sd, ok := s.Cache.Get("u" + digest(userSecret)); ok {
		return sd, nil
	}
	return nil, errNotFound
}

func (s *MemoryStore) ticketSecrets(t []byte) (string, string) {
	h, err := blake2b.New(32, s.secret())
	if err != nil {
		panic(err)
	}
	if _, err = h.Write(t); err != nil {
		panic(err)
	}
	d := h.Sum(nil)

	return hex.EncodeToString(d[:16]), hex.EncodeToString(d[16:])
}

func (s *MemoryStore) secret() []byte {
	s._initSecretOnce.Do(func() { s._secret = randBytes(32) })
	return s._secret
}

func digest[T string | []byte](d T) string {
	digest := blake2b.Sum256([]byte(d))
	return hex.EncodeToString(digest[:])
}

type PrefixMunger string

var _ UserSecretMunger = PrefixMunger("")

func (m PrefixMunger) UserSecretToURL(userSecret string) (url string) {
	return string(m) + userSecret
}

func (m PrefixMunger) UserSecretFromRequest(r *http.Request) (string, error) {
	userSecret, hadPrefix := strings.CutPrefix(r.URL.EscapedPath(), string(m))
	if !hadPrefix {
		return "", errors.New("bad request")
	}
	return userSecret, nil
}
