package se.distansakademin.cognito_oauth.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {


    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @GetMapping("/")
    public String getHomePage(Authentication auth, Model model) {

        if (auth == null) {
            model.addAttribute("loggedIn", false);
        } else {
            var username = auth.getName();

            model.addAttribute("loggedIn", true);
            model.addAttribute("username", username);
        }

        return "home";
    }

    @GetMapping("/auth-success")
    public String getLoginSuccess(OAuth2AuthenticationToken authentication) {

        var username = authentication.getName();
        var subject = authentication.getPrincipal().getAttribute("sub");

        // Här finns användaruppgifter i
        // OAuth2AuthenticationToken authentication

        return "redirect:/";
    }

    @GetMapping("/OLD")
    public String getOLD(OAuth2AuthenticationToken authentication) {

        var username = authentication.getName();
        var registrationId = authentication.getAuthorizedClientRegistrationId();
        var authorizedClient = authorizedClientService.loadAuthorizedClient(registrationId, username);

        var accessToken = authorizedClient.getAccessToken();

        return "redirect:/";
    }
}
