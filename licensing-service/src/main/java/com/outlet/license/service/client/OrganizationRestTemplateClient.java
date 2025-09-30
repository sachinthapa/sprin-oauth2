package com.outlet.license.service.client;

import com.outlet.license.model.Organization;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.io.IOException;

@Component
public class OrganizationRestTemplateClient {

    private final RestClient restClient;

    public OrganizationRestTemplateClient(@Qualifier("restClientOAuthIdentityProvider") RestClient restClient) {
        this.restClient = restClient;
    }

    public Organization getOrganizationWithDefaultAuthorizedClient(String organizationId) {
        return restClient.get()
                .uri("http://organization-service/v1/organization/" + organizationId)
                .retrieve()
                .onStatus(HttpStatusCode::is4xxClientError, new RestClient.ResponseSpec.ErrorHandler() {
                    @Override
                    public void handle(HttpRequest request, ClientHttpResponse response) throws IOException {
                        System.out.println("==========================OrganizationRestTemplateClient.handle");
                        try {
                            throw new Exception(response.getStatusCode().toString());// ,
                            // response.getHeaders())
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    }
                })
                .toEntity(Organization.class)
                .getBody();
    }

    // public Organization getOrganizationAuthorizedClient(OAuth2AuthorizedClient
    // authorizedClient,
    // String organizationId) {
    // return webClient.get()
    // .uri("http://localhost:8072/organization/v1/organization/" + organizationId)
    // // .headers(headers ->
    // // headers.setBearerAuth(authorizedClient.getAccessToken().getTokenValue()))
    //
    // .

    // attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
    // .retrieve()
    // .onStatus(HttpStatusCode::isError, error -> {
    // return Mono.error(new RuntimeException("Error fetching organization: " +
    // error.statusCode()));
    // })
    // .bodyToMono(Organization.class)
    // .onErrorResume(e -> {
    // throw new RuntimeException("Error fetching data: " + e.getMessage());
    // })
    // .block();
    // }

}
