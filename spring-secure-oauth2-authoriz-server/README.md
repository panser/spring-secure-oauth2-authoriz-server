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

## ЗАМЕЧАНИЯ
* хоть я и хотел создать лишь **Authorization server но** все равно пришлось использовать аннотацию **@EnableResourceServer** что бы експортировать `/user` ресурс, а он необходим для подключения к этому сервису сторонних  resource-сервисов через `security.oauth2.resource.user-info-uri`