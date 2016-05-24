package ua.org.gostroy.oauth2;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import ua.org.gostroy.oauth2.resourceserver.SpringSecureOauth2ResourceServerApplication;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = SpringSecureOauth2ResourceServerApplication.class)
@WebAppConfiguration
public class SpringSecureOauth2ResourceServerApplicationTests {

    @Test
    public void contextLoads() {
    }

}
