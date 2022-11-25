package com.zrs.aesauth.spi;

import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.userprofile.UserProfile;
import org.keycloak.userprofile.UserProfileContext;
import org.keycloak.userprofile.UserProfileProvider;
import org.keycloak.userprofile.ValidationException;
import org.keycloak.validate.ValidationError;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.client.RestTemplate;

import javax.ws.rs.core.MultivaluedMap;
import java.util.List;

public class RegistrationProfile implements FormAction, FormActionFactory {
    public static final String PROVIDER_ID = "registration-profile-action";
    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public String getHelpText() {
        return "Validates email, first name, and last name attributes and stores them in user data.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    @Override
    public void validate(org.keycloak.authentication.ValidationContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        context.getEvent().detail(Details.REGISTER_METHOD, "form");

        UserProfileProvider profileProvider = context.getSession().getProvider(UserProfileProvider.class);
        UserProfile profile = profileProvider.create(UserProfileContext.REGISTRATION_PROFILE, formData);


        final String uri =
                "https://intl-tel-input-8768.twil.io/lookup?phone=" +
                        profile.getAttributes().getFirstValue("phoneNumber");

        RestTemplate restTemplate = new RestTemplate();

        try {
            profile.validate();
        } catch (ValidationException pve) {
            List<FormMessage> errors = Validation.getFormErrorsFromValidation(pve.getErrors());


            if (pve.hasError(Messages.EMAIL_EXISTS, Messages.INVALID_EMAIL)) {
                context.getEvent().detail(Details.EMAIL, profile.getAttributes().getFirstValue(UserModel.EMAIL));
            }

            if (pve.hasError(Messages.EMAIL_EXISTS)) {
                context.error(Errors.EMAIL_IN_USE);
            }
            else
                context.error(Errors.INVALID_REGISTRATION);

            context.validationError(formData, errors);

            return;
        }

        try {
            ResponseEntity<String> response = restTemplate.getForEntity(uri, String.class);
            System.out.println(response);
        } catch (RestClientResponseException ex) {
            ValidationError ve = new ValidationError("211998", "phoneNumber", "Invalid phone number.");
            ValidationException vex = new ValidationException();
            vex.accept(ve);


            List<FormMessage> errors = Validation.getFormErrorsFromValidation(vex.getErrors());
            context.error(Errors.INVALID_REGISTRATION);

            context.validationError(formData, errors);

            return;
        }

        context.success();
    }

    @Override
    public void success(FormContext context) {
        UserModel user = context.getUser();
        UserProfileProvider provider = context.getSession().getProvider(UserProfileProvider.class);
        provider.create(UserProfileContext.REGISTRATION_PROFILE, context.getHttpRequest().getDecodedFormParameters(),
                user).update();
    }

    @Override
    public void buildPage(FormContext context, LoginFormsProvider form) {
        // complete
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public void close() {

    }

    @Override
    public String getDisplayType() {
        return "Profile Validation";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public FormAction create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}