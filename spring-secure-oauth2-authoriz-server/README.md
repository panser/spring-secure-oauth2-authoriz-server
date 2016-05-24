# Заметки

## получить токен
```
$ curl localhost:8080/oauth/token -d "grant_type=password&scope=read41&username=greg&password=turnquist" -u foo:bar
{"access_token":"1dda8c98-542a-4f11-b2cf-47b7a2bc3ee4","token_type":"bearer","refresh_token":"3a5ed4f4-89cd-400d-ac24-c0c6cd4b9592","expires_in":42323,"scope":"read4"}
```
в течение `expires_in` периода токены будут постоянными
```
$ curl localhost:8080/oauth/token -d "grant_type=password&scope=read4&username=greg&password=turnquist" -u foo:bar
{"access_token":"1dda8c98-542a-4f11-b2cf-47b7a2bc3ee4","token_type":"bearer","refresh_token":"3a5ed4f4-89cd-400d-ac24-c0c6cd4b9592","expires_in":42281,"scope":"read4"}
```
насчет переменных
* **grant_type** способ авторизации для получения токена (задаеться в spring-security)
    * **password** использовать user/password
* **scope** - не имеет значения какое (read, write, suck, read41), это лишь одна из переменных, которая будет проверяться в spring-security выражениях `@PreAuthorize("#oauth2.hasScope('read')") `
* **-u foo:bar** clientId:secretId

## используем токен
```
$ curl -H "Authorization: bearer 91b6102e-5758-45f3-a697-49a308db11d9" localhost:8080/user

{
	"details" : {
		"remoteAddress" : "0:0:0:0:0:0:0:1",
		"sessionId" : null,
		"tokenValue" : "91b6102e-5758-45f3-a697-49a308db11d9",
		"tokenType" : "bearer",
		"decodedDetails" : null
	},
	"authorities" : [{
			"authority" : "ROLE_USER"
		}
	],
	"authenticated" : true,
	"userAuthentication" : {
		"details" : {
			"grant_type" : "password",
			"scope" : "read",
			"username" : "greg"
		},
		"authorities" : [{
				"authority" : "ROLE_USER"
			}
		],
		"authenticated" : true,
		"principal" : {
			"password" : null,
			"username" : "greg",
			"authorities" : [{
					"authority" : "ROLE_USER"
				}
			],
			"accountNonExpired" : true,
			"accountNonLocked" : true,
			"credentialsNonExpired" : true,
			"enabled" : true
		},
		"credentials" : null,
		"name" : "greg"
	},
	"credentials" : "",
	"principal" : {
		"password" : null,
		"username" : "greg",
		"authorities" : [{
				"authority" : "ROLE_USER"
			}
		],
		"accountNonExpired" : true,
		"accountNonLocked" : true,
		"credentialsNonExpired" : true,
		"enabled" : true
	},
	"clientOnly" : false,
	"oauth2Request" : {
		"clientId" : "foo",
		"scope" : ["read"],
		"requestParameters" : {
			"grant_type" : "password",
			"scope" : "read",
			"username" : "greg"
		},
		"resourceIds" : [],
		"authorities" : [{
				"authority" : "ROLE_USER"
			}
		],
		"approved" : true,
		"refresh" : false,
		"redirectUri" : null,
		"responseTypes" : [],
		"extensions" : {},
		"grantType" : "password",
		"refreshTokenRequest" : null
	},
	"name" : "greg"
}

```

## TEORIA
### Tokens
сгенерированый токены должны где-то храниться, что бы отдавать их обратно втеченеии `expires_in` периода
 * **InMemoryTokenStore** умолчание
 * **JdbcTokenStore** в базе
 * **JSON Web Token (JWT)** хранит всю информацию внутри выдаррого токена (то есть - не нужно бекэнда)

### Endpoint URLs
 * **/oauth/authorize** (the authorization endpoint). should be protected using Spring Security so that it is only accessible to authenticated users.
 * **/oauth/token** (the token endpoint)
 * **/oauth/confirm_access** показываеться клиенту для подтверждения его намерений получить токен у сервиса
 * **/oauth/error** показывает ошибку при получении токена
 * **/oauth/check_token** used by Resource Servers to decode access tokens
 * **/oauth/token_key** (exposes public key for token verification if using JWT tokens)

## @EnableAuthorizationServer
для настройки сервиса раздающего токены
### AuthorizationServerEndpointsConfigurer
defines the authorization and token endpoints and the token services.
```
    @Autowired
    private AuthenticationManager authenticationManager;

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager);
    }
```
```
		@Value("${oauth.paths.token:/oauth/authorize}")
		private String tokenPath = "/oauth/token";

		@Value("${oauth.paths.token_key:/oauth/token_key}")
		private String tokenKeyPath = "/oauth/token_key";

		@Autowired
		private AuthenticationManager authenticationManager;

		@Autowired
		private ServerProperties server;

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			String prefix = server.getServletPrefix();
			endpoints.prefix(prefix);
			// @formatter:off
			endpoints.authenticationManager(authenticationManager)
				.pathMapping("/oauth/token", tokenPath)
				.pathMapping("/oauth/token_key", tokenKeyPath)
			// @formatter:on
		}
```
```
		@Autowired
		private AuthenticationManager authenticationManager;

		@Bean
		public JwtAccessTokenConverter accessTokenConverter() {
			return new JwtAccessTokenConverter();
		}

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints.authenticationManager(authenticationManager).accessTokenConverter(accessTokenConverter());
		}
```

### AuthorizationServerSecurityConfigurer
defines the security constraints on the token endpoint.
```
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.checkTokenAccess("isAnonymous()");
    }
```
```
		@Override
		public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
			oauthServer.checkTokenAccess("hasRole('ROLE_TRUSTED_CLIENT')");
		}
```
```
		@Override
		public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
			oauthServer.tokenKeyAccess("isAnonymous() || hasAuthority('ROLE_TRUSTED_CLIENT')").checkTokenAccess(
					"hasAuthority('ROLE_TRUSTED_CLIENT')");
		}
```


### ClientDetailsServiceConfigurer
для настройки ClientDetailsService
```
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
            .withClient(clientId)
                .secret(secretId)
                .authorizedGrantTypes("password", "authorization_code", "refresh_token", "implicit")
                .authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT")
                .scopes("read", "write", "trust")
                .resourceIds("oauth2-resource")
                .accessTokenValiditySeconds(600)
        .and()
...
```

`ClientDetailsServiceConfigurer`
* **inMemory/jdbc** место хранения user/password

`ClientBuilder`
* **withClient**  clientId
* **secret** secretId (если нету, то пустое)
```
$ curl localhost:8080/oauth/token -d "grant_type=password&scope=read&username=greg&password=turnquist" -u my-trusted-client
Enter host password for user 'my-trusted-client':
{"access_token":"19123715-71a2-4526-87c0-96ae2162b887","token_type":"bearer","refresh_token":"eb693287-4231-41f2-a35e-d219bacbb845","expires_in":599,"scope":"read"}
```
* **resourceIds**
* **redirectUris**
* **authorizedGrantTypes**  доступные типы авторизации на oauth2 сервисе. Default value is empty.
  * **password** по паролю
  * **client_credentials**  так же использовать clientId:secretId для доступа к ресурсу. не безопасно, и используеться лишь в тестовыз целях, к примеру для проверки работы endpoint, лучше использовать **password**
 ```
 $ curl acme:acmesecret@localhost:8080/oauth/token -d grant_type=client_credentials
 {"access_token":"370592fd-b9f8-452d-816a-4fd5c6b4b8a6","token_type":"bearer","expires_in":43199,"scope":"read write"}
 ```
  * **authorization_code**
  * **refresh_token**
  * **implicit**
* **accessTokenValiditySeconds** время жизни токена
* **refreshTokenValiditySeconds** время жизни токена
* **scopes**  scope to which the client is limited. If scope is undefined or empty (the default) the client is not limited by scope.
* **authorities**  роли spring-security
* **autoApprove**  не показывать окно подтверждения при входе, входить автоматом
* **additionalInformation**

### ЗАМЕЧАНИЯ
* хоть я и хотел создать лишь **Authorization server но** все равно пришлось использовать аннотацию **@EnableResourceServer** что бы експортировать `/user` ресурс, а он необходим для подключения к этому сервису сторонних  resource-сервисов через `security.oauth2.resource.user-info-uri` . Без этой аноттации `/user` ресурс експортируеться, но он доступен лишь через http-basic авторизацию, а не по токену
```
$ curl localhost:8080/oauth/token -d "grant_type=password&scope=read&username=greg&password=turnquist" -u foo:bar
{"access_token":"55849a83-b7a9-49ae-8584-3b61531d5674","token_type":"bearer","refresh_token":"57a647f4-b56c-4112-985e-767e51023e50","expires_in":599,"scope":"read"}
$ curl -H "Authorization: bearer 55849a83-b7a9-49ae-8584-3b61531d5674" localhost:8080/user
{"timestamp":1464077477180,"status":401,"error":"Unauthorized","message":"Full authentication is required to access this resource","path":"/user"}
```
это приводит к тому, что Resource-сервер не может получить информацию о клиенте, и соотвуетственно не может отдать свои ресурсы
```
$ curl -H "Authorization: bearer 55849a83-b7a9-49ae-8584-3b61531d5674" localhost:8083/testOauth2
{"error":"invalid_token","error_description":"55849a83-b7a9-49ae-8584-3b61531d5674"}
```


## @EnableResourceServer
для настройки доступа к определенным Oauth2 ресурсам
* **tokenServices**: the bean that defines the token services (instance of ResourceServerTokenServices).
* **resourceId**: the id for the resource (optional, but recommended and will be validated by the auth server if present).
* **tokenExtractor** for extracting the tokens from incoming requests)
```
	@Configuration
	@EnableResourceServer
	protected static class ResourceServer extends ResourceServerConfigurerAdapter {

		@Override
		public void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				// Just for laughs, apply OAuth protection to only 3 resources
				.requestMatchers().antMatchers("/","/admin/beans","/admin/health")
			.and()
				.authorizeRequests()
					.anyRequest().access("#oauth2.hasScope('read')");
			// @formatter:on
		}

		@Override
		public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
			resources.resourceId("sparklr");
		}

	}
```
```
		@Override
		public void configure(HttpSecurity http) throws Exception {
			http.authorizeRequests().anyRequest().authenticated();
		}
```

## @EnableOAuth2Client
для настройки клиента
```
	@Value("${oauth.resource:http://localhost:8080}")
	private String baseUrl;

	@Value("${oauth.authorize:http://localhost:8080/oauth/authorize}")
	private String authorizeUrl;

	@Value("${oauth.token:http://localhost:8080/oauth/token}")
	private String tokenUrl;

	@Autowired
	private OAuth2RestOperations restTemplate;

    @Bean
    public OAuth2RestOperations restTemplate(OAuth2ClientContext oauth2ClientContext) {
        return new OAuth2RestTemplate(resource(), oauth2ClientContext);
    }

    @Bean
    protected OAuth2ProtectedResourceDetails resource() {
        AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();
        resource.setAccessTokenUri(tokenUrl);
        resource.setUserAuthorizationUri(authorizeUrl);
        resource.setClientId("my-trusted-client");
        return resource ;
    }
```