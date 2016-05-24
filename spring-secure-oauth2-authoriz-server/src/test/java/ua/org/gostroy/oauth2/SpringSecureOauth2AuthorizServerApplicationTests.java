package ua.org.gostroy.oauth2;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import ua.org.gostroy.oauth2.authserver.SpringSecureOauth2AuthorizServerApplication;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = SpringSecureOauth2AuthorizServerApplication.class)
@WebAppConfiguration
public class SpringSecureOauth2AuthorizServerApplicationTests {

	@Test
	public void contextLoads() {
	}

}
