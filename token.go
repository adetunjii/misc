package misc

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

var (
	InvalidTokenError = errors.New("jwt is invalid")
	ExpiredJwtError   = errors.New("jwt has expired")
)

const minSecretKeySize = 32

type JwtFactory struct {
	SecretKey string
}

func NewJwtFactory(secretKey string) (*JwtFactory, error) {
	fmt.Println(secretKey)
	if len(secretKey) < minSecretKeySize {
		return nil, fmt.Errorf("invalid key size: must be at least %d characters", minSecretKeySize)
	}

	return &JwtFactory{SecretKey: secretKey}, nil
}

// TODO: investigage why env jwt secretkey breaks the code
func (j *JwtFactory) CreateToken(userInfo map[string]interface{}, duration time.Duration) (string, error) {
	payload, err := NewPayload(userInfo, duration)

	if err != nil {
		return "", err
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	return jwtToken.SignedString([]byte("secretkey"))
}

func (j *JwtFactory) VerifyToken(token string) (*Payload, error) {

	keyFunc := func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, InvalidTokenError
		}
		// return []byte(j.SecretKey), nil
		return []byte("secretkey"), nil
	}

	jwtToken, err := jwt.ParseWithClaims(token, &Payload{}, keyFunc)
	if err != nil {
		validationError, ok := err.(*jwt.ValidationError)
		if ok && errors.Is(validationError.Inner, ExpiredJwtError) {
			return nil, ExpiredJwtError
		}
		return nil, InvalidTokenError
	}

	payload, ok := jwtToken.Claims.(*Payload)
	if !ok {
		return nil, InvalidTokenError
	}
	return payload, nil
}

type Payload struct {
	ID        uuid.UUID              `json:"id"`
	User      map[string]interface{} `json:"user"`
	IssuedAt  time.Time              `json:"issued_at"`
	ExpiredAt time.Time              `json:"expired_at"`
}

func NewPayload(userInfo map[string]interface{}, duration time.Duration) (payload *Payload, err error) {
	tokenID, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	payload = &Payload{
		ID:        tokenID,
		User:      userInfo,
		IssuedAt:  time.Now(),
		ExpiredAt: time.Now().Add(duration),
	}
	return
}

func (p *Payload) Valid() error {
	if time.Now().After(p.ExpiredAt) {
		return ExpiredJwtError
	}
	return nil
}
