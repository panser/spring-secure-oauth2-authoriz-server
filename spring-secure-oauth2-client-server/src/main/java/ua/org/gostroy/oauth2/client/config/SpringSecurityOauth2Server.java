package ua.org.gostroy.oauth2.client.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;

/**
 * Created by Sergey on 5/25/2016.
 */
@Configuration
@EnableAuthorizationServer
@EnableResourceServer
public class SpringSecurityOauth2Server extends ResourceServerConfigurerAdapter {

    @Override
    public void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http
                .antMatcher("/me")
                .authorizeRequests().anyRequest().authenticated();
        // @formatter:on
    }
}
