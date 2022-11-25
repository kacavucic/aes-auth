package com.zrs.aesauth.spi;

import com.zrs.aesauth.spi.gateway.SmsServiceFactory;
import org.keycloak.authentication.*;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.credential.*;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.forms.login.freemarker.model.TotpBean;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.dto.OTPSecretData;
import org.keycloak.models.utils.TimeBasedOTP;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.*;

public class SmsOtpAuthenticator extends AbstractUsernameFormAuthenticator
        implements Authenticator, CredentialValidator<OTPCredentialProvider> {


    public static final String SELECTED_OTP_CREDENTIAL_ID = "selectedOtpCredentialId";
    public static final String UNNAMED = "unnamed";

    public SmsOtpAuthenticator() {
    }

    public void action(AuthenticationFlowContext context) {
        this.validateOTP(context);
    }

    public void authenticate(AuthenticationFlowContext context) {
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        UserModel user = context.getUser();

        String algorithm = "HmacSHA1";
        int numberDigits = 6;
        int timeIntervalInSeconds = 30;
        int lookAroundWindow = 1;
        TimeBasedOTP generator = new TimeBasedOTP(algorithm, numberDigits, timeIntervalInSeconds, lookAroundWindow);

        String senderId = "AES";
        boolean simulation = true;

        String phoneNumber = user.getFirstAttribute("phoneNumber");
        String phoneNumberMasked = phoneNumber.replaceAll(".(?=.{4})", "*");


        OTPCredentialModel
                defaultOTPCredential = (OTPCredentialModel) this.getCredentialProvider(context.getSession())
                .getDefaultCredential(context.getSession(), context.getRealm(), context.getUser());
        String credentialId = defaultOTPCredential == null ? "" : defaultOTPCredential.getId();

        UserCredentialStore userCredentialStore = session.userCredentialManager();
        CredentialModel credential = userCredentialStore.getStoredCredentialById(realm,user,credentialId);
        OTPCredentialModel otpCredentialModel = OTPCredentialModel.createFromCredentialModel(credential);
        OTPSecretData secretData = otpCredentialModel.getOTPSecretData();
        String secret = secretData.getValue();

//        TotpBean totpBean = new TotpBean(session, realm, user, null);
//        String totpSecret = totpBean.getTotpSecret();


//        OTPPolicy policy = context.getRealm().getOTPPolicy();
//        OTPCredentialModel credentialModel =
//                OTPCredentialModel.createFromPolicy(context.getRealm(), totpSecret, user.getUsername());

        String otp = generator.generateTOTP(secret);

        try {
            Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
            Locale locale = session.getContext().resolveLocale(user);
            String smsAuthText = theme.getMessages(locale).getProperty("smsAuthText");
            String smsText = String.format(smsAuthText, otp, 30);

            Map<String, String> config = new HashMap<>();
            config.put("length", String.valueOf(numberDigits));
            config.put("ttl", String.valueOf(timeIntervalInSeconds));
            config.put("senderId", senderId);
            config.put("simulation", String.valueOf(simulation));
            SmsServiceFactory.get(config).send(phoneNumber, smsText);


            Response challengeResponse =
                    context.form().setAttribute("phoneNumber", phoneNumberMasked)
                            .setAttribute("realm", context.getRealm()).createLoginTotp();
            context.challenge(challengeResponse);

        } catch (Exception e) {
            Response challengeResponse = context.form().setError("smsAuthSmsNotSent", e.getMessage())
                    .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                    challengeResponse);
        }

    }

    // TODO resend OTP i ovde i na config

    public void validateOTP(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();
        String otp = (String) inputData.getFirst("otp");
        String credentialId = (String) inputData.getFirst("selectedCredentialId");
        if (credentialId == null || credentialId.isEmpty()) {
            OTPCredentialModel
                    defaultOTPCredential = (OTPCredentialModel) this.getCredentialProvider(context.getSession())
                    .getDefaultCredential(context.getSession(), context.getRealm(), context.getUser());
            credentialId = defaultOTPCredential == null ? "" : defaultOTPCredential.getId();
        }

        context.getEvent().detail("selected_credential_id", credentialId);
        context.form().setAttribute("selectedOtpCredentialId", credentialId);
        UserModel userModel = context.getUser();
        if (this.enabledUser(context, userModel)) {
            if (otp == null) {
                Response challengeResponse = this.challenge(context, (String) null);
                context.challenge(challengeResponse);
            }
            else {
                boolean valid = context.getSession().userCredentialManager()
                        .isValid(context.getRealm(), context.getUser(), new CredentialInput[]{
                                new UserCredentialModel(credentialId,
                                        this.getCredentialProvider(context.getSession()).getType(), otp)});
                if (!valid) {
                    context.getEvent().user(userModel).error("invalid_user_credentials");
                    Response challengeResponse = this.challenge(context, "invalidTotpMessage", "totp");
                    context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
                }
                else {
                    context.success();
                }
            }
        }
    }

    public boolean requiresUser() {
        return true;
    }


    public OTPCredentialProvider getCredentialProvider(KeycloakSession session) {
        return (OTPCredentialProvider) session.getProvider(CredentialProvider.class, "keycloak-otp");
    }

    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return session.userCredentialManager()
                .isConfiguredFor(realm, user, this.getCredentialProvider(session).getType());

    }

    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        AuthenticationSessionModel authenticationSession = session.getContext().getAuthenticationSession();
        if (!authenticationSession.getRequiredActions().contains("verify-phone-number-ra")) {
            authenticationSession.addRequiredAction("verify-phone-number-ra");
        }

    }

    public List<RequiredActionFactory> getRequiredActions(KeycloakSession session) {
        return Collections.singletonList((RequiredActionFactory) session.getKeycloakSessionFactory()
                .getProviderFactory(RequiredActionProvider.class, "verify-phone-number-ra"));
    }

    public void close() {
    }

    protected Response createLoginForm(LoginFormsProvider form) {
        return form.createLoginTotp();
    }

    protected String disabledByBruteForceError() {
        return "invalidTotpMessage";
    }

    protected String disabledByBruteForceFieldError() {
        return "totp";
    }


}
