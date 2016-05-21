package ua.org.gostroy.oauth2.rest;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created by Sergey on 5/21/2016.
 */
@RestController
public class SomeResource {

    @RequestMapping("/testOauth2")
    public String testOauth2() {
        return "testOauth2";
    }

}
