package ua.org.gostroy.oauth2.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;

/**
 * Created by Sergey on 5/21/2016.
 */
@Configuration
@EnableAuthorizationServer
@EnableResourceServer
public class SpringSecurityOauth2 {
}
