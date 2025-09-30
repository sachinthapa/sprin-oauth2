package outlet.license;

import org.springframework.web.servlet.support.AbstractAnnotationConfigDispatcherServletInitializer;
import outlet.license.config.LicenseConfiguration;

public class LicenseServiceInitializer extends AbstractAnnotationConfigDispatcherServletInitializer {

    @Override
    protected Class<?>[] getRootConfigClasses() {
        return null;
    }

    @Override
    protected Class<?>[] getServletConfigClasses() {
        return new Class<?>[] { LicenseConfiguration.class };
    }

    @Override
    protected String[] getServletMappings() {
        return new String[] { "/" };
    }

}
