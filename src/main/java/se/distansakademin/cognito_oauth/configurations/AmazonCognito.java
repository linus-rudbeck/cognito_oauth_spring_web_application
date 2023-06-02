package se.distansakademin.cognito_oauth.configurations;

import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminUserGlobalSignOutRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.CognitoIdentityProviderException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.GlobalSignOutRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.RevokeTokenRequest;

public class AmazonCognito {
    public static CognitoIdentityProviderClient getCognitoClient() {
        var credentialsProvider = ProfileCredentialsProvider.create();

        var cognitoClient = CognitoIdentityProviderClient.builder()
                .region(Region.EU_NORTH_1)
                .credentialsProvider(credentialsProvider)
                .build();

        return cognitoClient;
    }

    public static boolean revokeToken(CognitoIdentityProviderClient cognitoClient, String clientId, String clientSecret, String token) {
        try {
            var request = RevokeTokenRequest.builder()
                    .clientId(clientId)
                    .clientSecret(clientSecret)
                    .token(token)
                    .build();

            cognitoClient.revokeToken(request);

            return true;

        } catch (CognitoIdentityProviderException e) {
            System.err.println(e.awsErrorDetails().errorMessage());
        }

        return false;
    }

}
