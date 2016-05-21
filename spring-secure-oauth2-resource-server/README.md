# Заметки

## доступ к ресурсу
так как включена авторизация то прямого доступа к ресурсу не получить
```
$ curl localhost:8083/testOauth2
{"error":"unauthorized","error_description":"Full authentication is required to access this resource"}
```

для начала необходимо получить Oauth2 токен из сервиса авторизации; и потом используя его обратиться к ресурсу
```
$ curl localhost:8080/oauth/token -d "grant_type=password&scope=read&username=greg&password=turnquist" -u foo:bar
{"access_token":"6a55a085-e5cf-43e5-a1c4-eebd07036b44","token_type":"bearer","refresh_token":"3e166329-450e-4257-bac3-86649288a915","expires_in":36413,"scope":"read"}
$ curl -H "Authorization: bearer 6a55a085-e5cf-43e5-a1c4-eebd07036b44" localhost:8083/testOauth2
testOauth2
```