import java.net.URI;
import java.net.URL;
import java.net.MalformedURLException;
import java.net.HttpURLConnection;

public class HealthCheck { 
    
    public static void main(String[] args) throws Exception {
        try {
            var url = new URI(args[0]).toURL();
            var connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("HEAD");
            var responseCode = connection.getResponseCode();
            System.out.println(responseCode == 200);
        } catch (Exception e) {
            throw e;
        }
    }
}

