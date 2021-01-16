package oauth2

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	uuid "github.com/gofrs/uuid"
)

const (
	TOKEN_TYPE = "Bearer"
)

type Any interface{}

type CredentialsVerifier interface {
	ValidateUser(username, password, scope string, req *http.Request) error
	ValidateClient(appid, secret, scope string, req *http.Request) error
	AddClaims(credential, tokenID, tokenType, scope string) (map[string]string, error)
	StoreTokenId(credential, tokenID, refreshTokenID, tokenType string) error
	ValidateTokenId(credential, tokenID, refreshTokenID, tokenType string) error
	ValidateResponseCode(appid, redirectURI, state, scope string) (int, interface{})
}

type AuthorizationCodeVerifier interface {
	ValidateCode(appid, secret, code string, req *http.Request) error
}

type OAuthBearerServer struct {
	secretKey string
	TokenTTL  time.Duration
	verifier  CredentialsVerifier
	provider  *TokenProvider
}

func NewOAuthBearerServer(secretKey string,
	ttl time.Duration,
	verifier CredentialsVerifier,
	formatter TokenSecureFormatter) *OAuthBearerServer {
	if formatter == nil {
		formatter = NewSHA256RC4TokenSecurityProvider([]byte(secretKey))
	}
	obs := &OAuthBearerServer{
		secretKey: secretKey,
		TokenTTL:  ttl,
		verifier:  verifier,
		provider:  NewTokenProvider(formatter)}
	return obs
}

func (s *OAuthBearerServer) UserCredentials(ctx *gin.Context) {
	grantType := ctx.Query("grant_type")
	username := ctx.Query("username")
	password := ctx.Query("password")
	code, resp := s.generateTokenResponse(grantType, username, password, "", "", "", "", ctx.Request)
	if code == http.StatusOK {
		Successful(ctx, resp)
		return
	}
	Fail(ctx, code, resp)
}

func (s *OAuthBearerServer) ClientCredentials(ctx *gin.Context) {
	grantType := ctx.Query("grant_type")
	appid := ctx.Query("appid")
	secret := ctx.Query("secret")
	scope := ctx.Query("scope")
	code, resp := s.generateTokenResponse(grantType, appid, secret, "", scope, "", "", ctx.Request)
	if code == http.StatusOK {
		Successful(ctx, resp)
		return
	}
	Fail(ctx, code, resp)
}

func (s *OAuthBearerServer) AuthorizationCode(ctx *gin.Context) {
	grantType := ctx.Query("grant_type")
	appid := ctx.Query("appid")
	secret := ctx.Query("secret")
	code := ctx.Query("code")
	// scope should come from Authorize when get code.
	scope := ctx.Query("scope")
	status, resp := s.generateTokenResponse(grantType, appid, secret, "", scope, code, "", ctx.Request)
	if status == http.StatusOK {
		Successful(ctx, resp)
		return
	}
	Fail(ctx, status, resp)
}

func (s *OAuthBearerServer) AuthAccessToken(ctx *gin.Context) {
	grantType := ctx.Query("grant_type")
	if grantType == "password" {
		s.UserCredentials(ctx)
	} else if grantType == "client_credentials" {
		s.ClientCredentials(ctx)
	} else if grantType == "authorization_code" {
		s.AuthorizationCode(ctx)
	} else {
		Fail(ctx, http.StatusInternalServerError, "grant_type is failed")
	}
}

func (s *OAuthBearerServer) Authorize(ctx *gin.Context) {
	appid := ctx.Query("appid")
	redirectURI := ctx.Query("redirect_uri")
	responseType := ctx.Query("response_type")
	state := ctx.Query("state")
	scope := ctx.Query("scope")

	if responseType != "code" || appid == "" || redirectURI == "" || scope == "" {
		Fail(ctx, http.StatusInternalServerError, "Missing parameter")
		return
	}
	status, resp := s.verifier.ValidateResponseCode(appid, redirectURI, state, scope)
	if status == http.StatusOK {
		ctx.Redirect(http.StatusMovedPermanently, resp.(string))
		return
	}
	Fail(ctx, status, resp)
}

func (s *OAuthBearerServer) AuthRefreshToken(ctx *gin.Context) {
	grantType := ctx.PostForm("grant_type")
	refreshToken := ctx.PostForm("refresh_token")

	status, resp := s.generateTokenResponse(grantType, "", "", refreshToken, "", "", "", ctx.Request)
	if status == http.StatusOK {
		Successful(ctx, resp)
		return
	}
	Fail(ctx, status, resp)
}

func (s *OAuthBearerServer) generateTokenResponse(grantType, credential, secret, refreshToken, scope, code, redirectURI string, req *http.Request) (int, Any) {
	if grantType == "password" {
		err := s.verifier.ValidateUser(credential, secret, scope, req)
		if err == nil {
			token, refresh, err := s.generateTokens(credential, "U", scope)
			if err == nil {
				err = s.verifier.StoreTokenId(credential, token.Id, refresh.RefreshTokenId, token.TokenType)
				if err != nil {
					return http.StatusInternalServerError, "Storing Token Id failed"
				}
				resp, err := s.cryptTokens(token, refresh)
				if err == nil {
					return http.StatusOK, resp
				} else {
					return http.StatusInternalServerError, "Token generation failed, check security provider"
				}
			} else {
				return http.StatusInternalServerError, "Token generation failed, check claims"
			}

		} else {
			return http.StatusUnauthorized, "Not authorized"
		}
	} else if grantType == "client_credentials" {
		err := s.verifier.ValidateClient(credential, secret, scope, req)
		if err == nil {
			token, refresh, err := s.generateTokens(credential, "C", scope)
			if err == nil {
				err = s.verifier.StoreTokenId(credential, token.Id, refresh.RefreshTokenId, token.TokenType)
				if err != nil {
					return http.StatusInternalServerError, "Storing Token Id failed"
				}
				resp, err := s.cryptTokens(token, refresh)
				if err == nil {
					return http.StatusOK, resp
				} else {
					return http.StatusInternalServerError, "Token generation failed, check security provider"
				}
			} else {
				return http.StatusInternalServerError, "Token generation failed, check claims"
			}
		} else {
			return http.StatusUnauthorized, "Not authorized"
		}
	} else if grantType == "authorization_code" {
		if codeVerifier, ok := s.verifier.(AuthorizationCodeVerifier); ok {
			err := codeVerifier.ValidateCode(credential, secret, code, req)
			if err == nil {
				token, refresh, err := s.generateTokens(credential, "A", scope)
				if err == nil {
					err = s.verifier.StoreTokenId(credential, token.Id, refresh.RefreshTokenId, token.TokenType)
					if err != nil {
						return http.StatusInternalServerError, "Storing Token Id failed"
					}
					resp, err := s.cryptTokens(token, refresh)
					if err == nil {
						return http.StatusOK, resp
					} else {
						return http.StatusInternalServerError, "Token generation failed, check security provider"
					}
				} else {
					return http.StatusInternalServerError, "Token generation failed, check claims"
				}
			} else {
				return http.StatusUnauthorized, "Not authorized"
			}
		} else {
			return http.StatusUnauthorized, "Not authorized, grant type not supported"
		}
	} else if grantType == "refresh_token" {
		refresh, err := s.provider.DecryptRefreshTokens(refreshToken)
		if err == nil {
			err = s.verifier.ValidateTokenId(refresh.Credential, refresh.TokenId, refresh.RefreshTokenId, refresh.TokenType)
			if err == nil {
				token, refresh, err := s.generateTokens(refresh.Credential, refresh.TokenType, refresh.Scope)
				if err == nil {
					err = s.verifier.StoreTokenId(refresh.Credential, token.Id, refresh.RefreshTokenId, token.TokenType)
					if err != nil {
						return http.StatusInternalServerError, "Storing Token Id failed"
					}
					resp, err := s.cryptTokens(token, refresh)
					if err == nil {
						return http.StatusOK, resp
					} else {
						return http.StatusInternalServerError, "Token generation failed"
					}
				} else {
					return http.StatusInternalServerError, "Token generation failed"
				}
			} else {
				return http.StatusUnauthorized, "Not authorized invalid token"
			}
		} else {
			return http.StatusUnauthorized, "Not authorized"
		}
	} else {
		return http.StatusBadRequest, "Invalid grant_type"
	}
}

func (s *OAuthBearerServer) generateTokens(username, tokenType, scope string) (token *Token, refresh *RefreshToken, err error) {
	token = &Token{Credential: username, ExperesIn: s.TokenTTL, CreationDate: time.Now().UTC(), TokenType: tokenType, Scope: scope}
	token.Id = uuid.Must(uuid.NewV4()).String()
	if s.verifier != nil {
		claims, err := s.verifier.AddClaims(username, token.Id, token.TokenType, token.Scope)
		if err == nil {
			token.Claims = claims
		} else {
			return nil, nil, err
		}
	}
	refresh = &RefreshToken{RefreshTokenId: uuid.Must(uuid.NewV4()).String(), TokenId: token.Id, CreationDate: time.Now().UTC(), Credential: username, TokenType: tokenType, Scope: scope}

	return token, refresh, nil
}

func (s *OAuthBearerServer) cryptTokens(token *Token, refresh *RefreshToken) (resp *TokenResponse, err error) {
	ctoken, err := s.provider.CryptToken(token)
	if err != nil {
		return nil, err
	}
	crefresh, err := s.provider.CryptRefreshToken(refresh)
	if err != nil {
		return nil, err
	}
	resp = &TokenResponse{Token: ctoken, RefreshToken: crefresh, TokenType: TOKEN_TYPE, ExperesIn: (int64)(s.TokenTTL / time.Second)}
	return resp, nil
}
