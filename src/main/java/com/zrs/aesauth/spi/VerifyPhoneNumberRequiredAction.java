package com.zrs.aesauth.spi;

import com.zrs.aesauth.spi.email.EmailServiceImpl;
import com.zrs.aesauth.spi.email.IEmailService;
import com.zrs.aesauth.spi.gateway.SmsServiceFactory;
import com.zrs.aesauth.spi.sms.ISmsService;
import com.zrs.aesauth.spi.sms.SmsServiceImpl;
import org.keycloak.Config.Scope;
import org.keycloak.authentication.*;
import org.keycloak.authentication.requiredactions.ConsoleUpdateTotp;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.OTPCredentialProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.freemarker.model.TotpBean;
import org.keycloak.models.*;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.utils.CredentialValidation;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.models.utils.TimeBasedOTP;
import org.keycloak.services.validation.Validation;
import org.keycloak.theme.Theme;
import org.keycloak.utils.CredentialHelper;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;

public class VerifyPhoneNumberRequiredAction
        implements RequiredActionProvider, RequiredActionFactory, DisplayTypeRequiredActionFactory,
        CredentialRegistrator {

    public static final String PROVIDER_ID = "verify-phone-number-ra";
    private static final String TPL_CODE = "login-config-sms.ftl";
    IEmailService emailService;
    ISmsService smsService;

    public VerifyPhoneNumberRequiredAction() {
        emailService = new EmailServiceImpl();
        smsService = new SmsServiceImpl();
    }

    public InitiatedActionSupport initiatedActionSupport() {
        return InitiatedActionSupport.SUPPORTED;
    }

    public void evaluateTriggers(RequiredActionContext context) {
    }

    @SuppressWarnings("DuplicatedCode")
    public void requiredActionChallenge(RequiredActionContext context) {
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

        TotpBean totpBean = new TotpBean(session, realm, user, null);
        String totpSecret = totpBean.getTotpSecret();

        String otp = generator.generateTOTP(totpSecret);

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

            smsService.sendVerifyPhoneNumberSms(user.getFirstAttribute("firstName"), otp, user.getFirstAttribute("phoneNumber"));
            emailService.sendVerifyPhoneNumberEmail(user.getFirstAttribute("firstName"), otp, user.getEmail());
            SmsServiceFactory.get(config).send(phoneNumber, smsText);

            Response challengeResponse =
                    context.form().setAttribute("phoneNumber", phoneNumberMasked)
                            .setAttribute("totpSecret", totpSecret)
                            .setAttribute("realm", context.getRealm())
                            .setAttribute("mode", context.getUriInfo().getQueryParameters().getFirst("mode"))
                            .createForm(TPL_CODE);
            context.challenge(challengeResponse);
        } catch (Exception e) {

            Response challengeResponse = context.form()
                    .addError(new FormMessage("totp", "smsAuthSmsNotSent"))
                    .createForm(TPL_CODE);
            context.challenge(challengeResponse);

        }
    }

    public void processAction(RequiredActionContext context) {
        UserModel user = context.getUser();
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();

        String phoneNumber = user.getFirstAttribute("phoneNumber");
        String phoneNumberMasked = phoneNumber.replaceAll(".(?=.{4})", "*");

        EventBuilder event = context.getEvent();
        event.event(EventType.UPDATE_TOTP);
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String challengeResponse = (String) formData.getFirst("totp");
        String totpSecret = (String) formData.getFirst("totpSecret");
        String mode = (String) formData.getFirst("mode");
        String userLabel = (String) formData.getFirst("userLabel");
        OTPPolicy policy = context.getRealm().getOTPPolicy();
        OTPCredentialModel credentialModel =
                OTPCredentialModel.createFromPolicy(context.getRealm(), totpSecret, userLabel);

        if (Validation.isBlank(challengeResponse)) {
//            TotpBean totpBean = new TotpBean(session, realm, user, null);
            Response challenge =
                    context.form().setAttribute("mode", mode).setAttribute("phoneNumber", phoneNumberMasked)
                            .setAttribute("realm", context.getRealm()).setAttribute("totpSecret", totpSecret)
                            .addError(new FormMessage("totp", "missingTotpMessage"))
                            .createForm(TPL_CODE);
            context.challenge(challenge);
        }
        else if (!this.validateOTPCredential(context, challengeResponse, credentialModel, policy)) {
//            TotpBean totpBean = new TotpBean(session, realm, user, null);
            Response challenge =
                    context.form().setAttribute("mode", mode).setAttribute("phoneNumber", phoneNumberMasked)
                            .setAttribute("realm", context.getRealm()).setAttribute("totpSecret", totpSecret)
                            .addError(new FormMessage("totp", "invalidTotpMessage"))
                            .createForm(TPL_CODE);
            context.challenge(challenge);
        }
        else {
            OTPCredentialProvider otpCredentialProvider =
                    (OTPCredentialProvider) context.getSession().getProvider(CredentialProvider.class, "keycloak-otp");
            Stream<CredentialModel> otpCredentials =
                    otpCredentialProvider.isConfiguredFor(context.getRealm(), context.getUser()) ?
                            context.getSession().userCredentialManager()
                                    .getStoredCredentialsByTypeStream(context.getRealm(), context.getUser(), "otp") :
                            Stream.empty();

            if (otpCredentials.count() >= 1L && Validation.isBlank(userLabel)) {
//                TotpBean totpBean = new TotpBean(session, realm, user, null);
                Response challenge =
                        context.form().setAttribute("mode", mode).setAttribute("phoneNumber", phoneNumberMasked)
                                .setAttribute("realm", context.getRealm()).setAttribute("totpSecret", totpSecret)
                                .addError(new FormMessage("userLabel", "missingTotpDeviceNameMessage"))
                                .createForm(TPL_CODE);
                context.challenge(challenge);
            }
            else if (!CredentialHelper.createOTPCredential(context.getSession(), context.getRealm(), context.getUser(),
                    challengeResponse, credentialModel)) {
//                TotpBean totpBean = new TotpBean(session, realm, user, null);
                Response challenge =
                        context.form().setAttribute("mode", mode).setAttribute("phoneNumber", phoneNumberMasked)
                                .setAttribute("realm", context.getRealm()).setAttribute("totpSecret", totpSecret)
                                .addError(new FormMessage("totp", "invalidTotpMessage"))
                                .createForm(TPL_CODE);
                context.challenge(challenge);
            }
            else {
                context.success();
            }
        }
    }

    protected boolean validateOTPCredential(RequiredActionContext context, String token,
                                            OTPCredentialModel credentialModel, OTPPolicy policy) {
        return CredentialValidation.validOTP(token, credentialModel, policy.getLookAheadWindow());
    }

    public void close() {
    }

    public RequiredActionProvider create(KeycloakSession session) {
        return this;
    }

    public RequiredActionProvider createDisplay(KeycloakSession session, String displayType) {
        if (displayType == null) {
            return this;
        }
        else {
            return !"console".equalsIgnoreCase(displayType) ? null : ConsoleUpdateTotp.SINGLETON;
        }
    }

    public void init(Scope config) {
    }

    public void postInit(KeycloakSessionFactory factory) {
    }

    public String getDisplayText() {
        return "Configure SMS OTP";
    }

    public String getId() {
        return PROVIDER_ID;
    }

    public boolean isOneTimeAction() {
        return true;
    }
}
