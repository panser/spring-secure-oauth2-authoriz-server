package ua.org.gostroy.oauth2.clientspringboot.rest;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * Created by Sergey on 5/21/2016.
 */
@RestController
public class UserInfo {

    @RequestMapping("/user")
    public Principal user(Principal user) {
        return user;
    }

}
