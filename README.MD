# oauth2 中间件

适用于 [Gin-Gonic](https://github.com/gin-gonic/gin) 的OAuth 2.0授权服务器和授权中间件

该库提供了基于Gin-Gonic的OAuth 2.0授权服务器以及可在与Gin-Gonic开发的资源服务器中使用的授权中间件。

## 授权服务器

授权服务器由OAuthBearerServer结构实现，该结构管理两种授权类型的授权（password和client_credentials）。使该授权服务器提供可用于消耗资源API的授权令牌。

### 密码授予类型

OAuthBearerServer支持密码授予类型，允许为用户名/密码凭证生成令牌。

### 客户凭证授予类型

OAuthBearerServer支持client_credentials授予类型，允许为appid/secret凭证生成令牌。

### 授权码和隐式授予类型

实现支持AuthorizationCodeVerifier接口的这些授权类型。ValidateResponseCode一阶段调用，ValidateCode方法在授权代码授予类型评估的第二阶段被调用。

### 刷新令牌授予类型

如果授权令牌将过期，则客户端可以通过调用授权服务器并使用refresh_token授予类型来重新生成令牌。

## 授权中间件

Gin-Gonic中间件BearerAuthentication拦截资源服务器调用，并仅授权包含有效承载令牌的资源请求。

## 令牌格式化程序

授权服务器使用令牌格式化程序对令牌进行加密，而授权中间件使用相同的令牌格式化程序对令牌进行解密。该库包含基于算法SHA256和RC4的名为_ SHA256RC4TokenSecureFormatter_的格式化程序接口的默认实现。程序员可以开发自己的Token Formatter，以实现TokenSecureFormatter接口，在生产环境中发布API之前，确实建议这样做。

## 凭证验证器

首先调用ValidateUser()或ValidateClient()进行凭据验证

AddClaims()用于将信息添加到将被加密的令牌中

StoreTokenId()的令牌生成之后，但在反应之前被调用，程序员可以使用用于存储生成的ID有一个在另一种方法中此方法CredentialsVerifier它们是在刷新令牌过程涉及接口。在这种情况下，将按以下顺序调用方法：

首先调用TokenId验证的ValidateTokenId()，该方法接收与刷新令牌相关的令牌相关的TokenId

AddClaims()用于将信息添加到将被加密的令牌中

在令牌重新生成之后但在响应之前调用的StoreTokenId()，程序员可以使用此方法存储生成的ID

## 授权服务器使用示例



有关完整示例，请参见 [test.txt](https://github.com/asoow/oauth2/blob/master/test.txt) 

请注意，授权服务器和授权中间件都使用相同的令牌格式化程序和相同的密钥进行加密/解密。

## Reference

- [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749)
- [OAuth 2.0 Bearer Token Usage RFC](https://tools.ietf.org/html/rfc6750)

## License

[MIT](https://github.com/asoow/oauth2/blob/master/LICENSE)