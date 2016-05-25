# INFO

обязательно должен быть запущен oauth2 сервер **spring-secure-oauth2-authoriz-server** или **spring-secure-oauth2-client-server** http://localhost:8080/

для тестирования клиента перейдите по ссылке http://localhost:8084/client/
```
The context path has to be explicit if you are running both the client and the auth server on localhost, otherwise the cookie paths clash and the two apps cannot agree on a session identifier.
```

Или можно в spring-boot отключить context-path
```
#application.yml
    #  context-path: /client
#index.html
    <!--<base href="/client/"/>-->
```
но тогда можно будеть тестировать клиента лишь по ip-адрессу http://127.0.0.1:8084/
```
Don’t use "localhost" for the test client app or it will steal cookies from the main app and mess up the authentication.
```