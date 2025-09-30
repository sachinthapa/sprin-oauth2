package outlet.license.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

@Configuration
@ComponentScan("outlet.license")
@EnableWebMvc
public class LicenseConfiguration {

}
