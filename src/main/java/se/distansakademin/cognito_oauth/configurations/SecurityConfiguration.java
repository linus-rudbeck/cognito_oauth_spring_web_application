package se.distansakademin.cognito_oauth.configurations;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;

@Configuration
public class SecurityConfiguration {

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .requestMatchers("/", "/login-success").permitAll()
                .anyRequest().authenticated();



        http.oauth2Login()
                .defaultSuccessUrl("/auth-success");


        var logoutSuccessHandler = new CognitoLogoutSuccessHandler(clientRegistrationRepository);

        http.logout()
                .logoutSuccessHandler(logoutSuccessHandler);

        return http.build();
    }
}


class CognitoLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler{

    private ClientRegistrationRepository clientRegistrationRepository;

    public CognitoLogoutSuccessHandler(ClientRegistrationRepository clientRegistrationRepository) {
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication){
        var oauth2Token = (OAuth2AuthenticationToken) authentication;

        var clientRegistration = getClientRegistration(oauth2Token);
        
        var logoutUrl = getLogoutUrl(clientRegistration);
        var clientId = clientRegistration.getClientId();

        var basePath = ServletUriComponentsBuilder.fromRequestUri(request)
                .replacePath(null)
                .build()
                .toUriString();


        var targetUrl = UriComponentsBuilder
                .fromUri(URI.create(logoutUrl))
                .queryParam("client_id", clientId)
                .queryParam("logout_uri", basePath + "/")
                .toUriString();

        return targetUrl;
    }

    private String getLogoutUrl(ClientRegistration clientRegistration) {
        var providerDetails = clientRegistration.getProviderDetails();
        var authUri = providerDetails.getAuthorizationUri();
        return authUri.replace("oauth2/authorize", "logout");
    }

    private ClientRegistration getClientRegistration(OAuth2AuthenticationToken token){
        var registrationId = token.getAuthorizedClientRegistrationId();
        return clientRegistrationRepository.findByRegistrationId(registrationId);
    }

}