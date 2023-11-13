package tp

import (
	"context"
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
	Insert(context.Context, *StoreData) (userSecret, pollSecret string, err error)

	GetByPollSecret(context.Context, string) (*StoreData, error)
	GetByUserSecret(context.Context, string) (*StoreData, error)

	UpdateByPollSecret(context.Context, string, *StoreData) error
	UpdateByUserSecret(context.Context, string, *StoreData) error

	DeleteByPollSecret(context.Context, string) error
	DeleteByUserSecret(context.Context, string) error

	UserSecretMunger
}

type UserSecretMunger interface {
	UserSecretToURL(userSecret string) (url string)
	UserSecretFromRequest(r *http.Request) (string, error)
}

type MemoryStore struct {
	UserSecretMunger
	Cache *lru.Cache[string, *lockedStoreData]
}

func NewMemoryStore(m UserSecretMunger, size int) (*MemoryStore, error) {
	cache, err := lru.New[string, *lockedStoreData](size)
	if err != nil {
		return nil, err
	}

	return &MemoryStore{
		Cache:            cache,
		UserSecretMunger: m,
	}, nil
}

var _ Store = (*MemoryStore)(nil)

var (
	errNotFound = errors.New("not found")
)

const secretSize = 16

func (s *MemoryStore) Insert(_ context.Context, sd *StoreData) (string, string, error) {
	us := randHex(secretSize)
	uk := userSecretKey(us)
	ps := randHex(secretSize)
	pk := pollSecretKey(ps)

	lsd := &lockedStoreData{
		StoreData:     *sd,
		userSecretKey: uk,
		pollSecretKey: pk,
	}

	s.Cache.Add(uk, lsd)
	s.Cache.Add(pk, lsd)

	return us, ps, nil
}

func (s *MemoryStore) GetByPollSecret(_ context.Context, pollSecret string) (*StoreData, error) {
	lsd, _ := s.Cache.Get(pollSecretKey(pollSecret))
	return lsd.getStoreData()
}

func (s *MemoryStore) GetByUserSecret(_ context.Context, userSecret string) (*StoreData, error) {
	lsd, _ := s.Cache.Get(userSecretKey(userSecret))
	return lsd.getStoreData()
}

func (s *MemoryStore) UpdateByPollSecret(_ context.Context, pollSecret string, sd *StoreData) error {
	lsd, _ := s.Cache.Get(pollSecretKey(pollSecret))
	return lsd.updateStoreData(sd)
}

func (s *MemoryStore) UpdateByUserSecret(_ context.Context, userSecret string, sd *StoreData) error {
	lsd, _ := s.Cache.Get(userSecretKey(userSecret))
	return lsd.updateStoreData(sd)
}

func (s *MemoryStore) DeleteByPollSecret(ctx context.Context, pollSecret string) error {
	if lsd, _ := s.Cache.Get(pollSecretKey(pollSecret)); lsd != nil {
		s.Cache.Remove(lsd.pollSecretKey)
		s.Cache.Remove(lsd.userSecretKey)
		return nil
	}

	return errNotFound
}

func (s *MemoryStore) DeleteByUserSecret(ctx context.Context, userSecret string) error {
	if lsd, _ := s.Cache.Get(userSecretKey(userSecret)); lsd != nil {
		s.Cache.Remove(lsd.pollSecretKey)
		s.Cache.Remove(lsd.userSecretKey)
		return nil
	}

	return errNotFound
}

func userSecretKey(userSecret string) string { return "u" + digest(userSecret) }
func pollSecretKey(userSecret string) string { return "p" + digest(userSecret) }

type lockedStoreData struct {
	StoreData
	userSecretKey string
	pollSecretKey string
	sync.RWMutex
}

func (lsd *lockedStoreData) getStoreData() (*StoreData, error) {
	if lsd == nil {
		return nil, errNotFound
	}

	lsd.RLock()
	defer lsd.RUnlock()

	sd := lsd.StoreData

	return &sd, nil
}

func (lsd *lockedStoreData) updateStoreData(sd *StoreData) error {
	if lsd == nil {
		return errNotFound
	}

	lsd.Lock()
	defer lsd.Unlock()

	lsd.StoreData = *sd

	return nil
}

func digest[T string | []byte](d T) string {
	digest := blake2b.Sum256([]byte(d))
	return hex.EncodeToString(digest[:])
}

func randHex(n int) string {
	return hex.EncodeToString(randBytes(n))
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
