package oauth2

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type BearerAuthentication struct {
	secretKey string
	provider  *TokenProvider
}

func NewBearerAuthentication(secretKey string, formatter TokenSecureFormatter) *BearerAuthentication {
	ba := &BearerAuthentication{secretKey: secretKey}
	if formatter == nil {
		formatter = NewSHA256RC4TokenSecurityProvider([]byte(secretKey))
	}
	ba.provider = NewTokenProvider(formatter)
	return ba
}

func Authorize(secretKey string, formatter TokenSecureFormatter) gin.HandlerFunc {
	return NewBearerAuthentication(secretKey, nil).Authorize
}

func (ba *BearerAuthentication) Authorize(ctx *gin.Context) {
	auth := ctx.Request.Header.Get("Authorization")
	token, err := ba.checkAuthorizationHeader(auth)
	if err != nil {
		Fail(ctx, http.StatusUnauthorized, "Not authorized: "+err.Error())
	} else {
		ctx.Set("oauth.credential", token.Credential)
		ctx.Set("oauth.claims", token.Claims)
		ctx.Set("oauth.scope", token.Scope)
		ctx.Set("oauth.tokentype", token.TokenType)
		ctx.Set("oauth.accesstoken", auth[7:])
		ctx.Next()
	}
}

func (ba *BearerAuthentication) checkAuthorizationHeader(auth string) (t *Token, err error) {
	if len(auth) < 7 {
		return nil, errors.New("Invalid bearer authorization header")
	}
	authType := strings.ToLower(auth[:6])
	if authType != "bearer" {
		return nil, errors.New("Invalid bearer authorization header")
	}
	token, err := ba.provider.DecryptToken(auth[7:])
	if err != nil {
		return nil, errors.New("Invalid token")
	}
	if time.Now().UTC().After(token.CreationDate.Add(token.ExperesIn)) {
		return nil, errors.New("Token expired")
	}
	return token, nil
}

type TokenResponse struct {
	Token        string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExperesIn    int64  `json:"expires_in"`
}

type Token struct {
	Id           string            `json:"id_token"`
	CreationDate time.Time         `json:"date"`
	ExperesIn    time.Duration     `json:"expires_in"`
	Credential   string            `json:"credential"`
	Scope        string            `json:"scope"`
	Claims       map[string]string `json:"claims"`
	TokenType    string            `json:"type"`
}

type RefreshToken struct {
	CreationDate   time.Time `json:"date"`
	TokenId        string    `json:"id_token"`
	RefreshTokenId string    `json:"id_refresh_token"`
	Credential     string    `json:"credential"`
	TokenType      string    `json:"type"`
	Scope          string    `json:"scope"`
}

func Fail(c *gin.Context, code, message interface{}) {
	c.JSON(http.StatusOK, gin.H{
		"success":      false,
		"errorCode":    code,
		"errorMessage": message,
	})
	c.Abort()
	return
}

func Successful(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"errorMessage": "",
		"data":         data,
	})
	return
}
