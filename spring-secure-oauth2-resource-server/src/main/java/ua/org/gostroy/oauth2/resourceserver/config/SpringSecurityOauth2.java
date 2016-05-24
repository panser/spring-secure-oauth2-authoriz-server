package ua.org.gostroy.oauth2.resourceserver.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;

/**
 * Created by Sergey on 5/21/2016.
 */
@Configuration
@EnableResourceServer
public class SpringSecurityOauth2 extends ResourceServerConfigurerAdapter {

    @Override
    public void configure(HttpSecurity http) throws Exception {

        http
            .antMatcher("/me")
            .authorizeRequests().anyRequest().authenticated();
    }
}
