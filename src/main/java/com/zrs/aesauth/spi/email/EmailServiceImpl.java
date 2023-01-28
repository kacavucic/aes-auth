package com.zrs.aesauth.spi.email;

import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.ITemplateEngine;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring5.SpringTemplateEngine;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import java.util.Properties;
import java.util.logging.Logger;


@Service
public class EmailServiceImpl implements IEmailService {

    private static final Logger logger = Logger.getLogger(EmailServiceImpl.class.getName());

    private static final String NOREPLY_ADDRESS = "kacafon98@gmail.com";

    private final JavaMailSender emailSender;

    private final ITemplateEngine thymeleafTemplateEngine;

    private String emailUsername;

    private String emailPassword;

    public EmailServiceImpl() {
        this.emailUsername = System.getenv("mail_username");
        this.emailPassword = System.getenv("mail_password");

        emailSender = new JavaMailSenderImpl();
        ((JavaMailSenderImpl) emailSender).setHost("smtp.gmail.com");
        ((JavaMailSenderImpl) emailSender).setPort(587);
        ((JavaMailSenderImpl) emailSender).setUsername(emailUsername);
        ((JavaMailSenderImpl) emailSender).setPassword(emailPassword);
        Properties props = ((JavaMailSenderImpl) emailSender).getJavaMailProperties();
//        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
//        props.put("mail.debug", "true");
        thymeleafTemplateEngine = new SpringTemplateEngine();
    }

    // TODO skarij iz application.yml kredencijale i odavde za smtp server

    @Override
    public void sendOTPEmail(String firstName, String otp, String email)
            throws MessagingException {

        Context context = new Context();
        context.setVariable("user_first_name", firstName);
        context.setVariable("otp", otp);

        logger.info("Start processing otpEmail.html template");
        String htmlBody = thymeleafTemplateEngine.process("<!doctype html>\n" +
                "<html lang=\"en\" xmlns=\"http://www.w3.org/1999/xhtml\"\n" +
                "      xmlns:th=\"http://www.thymeleaf.org\">\n" +
                "<head>\n" +
                "    <title>Email</title>\n" +
                "    <meta content=\"text/html\" http-equiv=\"Content-Type\"/>\n" +
                "    <meta charset=\"UTF-8\"/>\n" +
                "    <meta content=\"width=device-width, initial-scale=1\" name=\"viewport\">\n" +
                "    <meta content=\"IE=edge\" http-equiv=\"X-UA-Compatible\"/>\n" +
                "    <link crossorigin=\"anonymous\" href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta.2/css/bootstrap.min.css\"\n" +
                "          integrity=\"sha384-PsH8R72JQ3SOdhVi3uxftmaW6Vc51MKb0q5P2rRUpPvrszuE4W1povHYgTpBfshb\" rel=\"stylesheet\">\n" +
                "</head>\n" +
                "<body style=\"min-height: 100vh;margin: 0 !important; padding: 0 !important;\n" +
                "background-color: white\">\n" +
                "<div class=\"row\" style=\"padding-top: 25px\">\n" +
                "    <div class=\"card col-xs-12 offset-xs-0 col-md-4 offset-md-4\">\n" +
                "        <div class=\"card-body\">\n" +
                "            <div>\n" +
                "                <h1 class=\"card-title\" style=\"padding-left: 10px;\">AES - Authentication</h1>\n" +
                "                <img src=\"https://img.icons8.com/ios-filled/90/4a90e2/one-time-password.png\"\n" +
                "                     style=\"padding-left: 10px;\" alt=\"one-time-password\"/>\n" +
                "            </div>\n" +
                "            <div>\n" +
                "                <p style=\"color: #000000 !important; padding-left: 10px;\"><b th:text=\"${user_first_name}\"></b>, please\n" +
                "                    use the\n" +
                "                    following\n" +
                "                    OTP to authenticate to AES.</p>\n" +
                "                <p style=\"color: #000000 !important; padding-left: 10px;\">\n" +
                "                    Your OTP: <b th:text=\"${otp}\"></b>\n" +
                "                </p>\n" +
                "                <p style=\"color: #000000 !important; padding-left: 10px;\"><i>Note</i>: OTP is valid for 30 seconds.\n" +
                "                </p>\n" +
                "\n" +
                "                <p style=\"color: #000000 !important; padding-left: 10px;\">\n" +
                "                    Best Regards,<br>\n" +
                "                    AES Team\n" +
                "                </p>\n" +
                "            </div>\n" +
                "        </div>\n" +
                "\n" +
                "    </div>\n" +
                "</div>\n" +
                "</body>\n" +
                "</html>\n" +
                "\n" +
                "\n" +
                "\n", context);
        logger.info("otpEmail.html template processed successfully");

        MimeMessage message = emailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
        helper.setFrom(NOREPLY_ADDRESS);
        helper.setTo(email);
        helper.setSubject("[AES] OTP");
        helper.setText(htmlBody, true);
        //helper.addInline("attachment.png", resourceFile);
        emailSender.send(message);
    }

    @Override
    public void sendVerifyPhoneNumberEmail(String firstName, String otp, String email) throws MessagingException {
        Context context = new Context();
        context.setVariable("user_first_name", firstName);
        context.setVariable("otp", otp);

        logger.info("Start processing otpEmail.html template");
        String htmlBody = thymeleafTemplateEngine.process("<!doctype html>\n" +
                "<html lang=\"en\" xmlns=\"http://www.w3.org/1999/xhtml\"\n" +
                "      xmlns:th=\"http://www.thymeleaf.org\">\n" +
                "<head>\n" +
                "    <title>Email</title>\n" +
                "    <meta content=\"text/html\" http-equiv=\"Content-Type\"/>\n" +
                "    <meta charset=\"UTF-8\"/>\n" +
                "    <meta content=\"width=device-width, initial-scale=1\" name=\"viewport\">\n" +
                "    <meta content=\"IE=edge\" http-equiv=\"X-UA-Compatible\"/>\n" +
                "    <link crossorigin=\"anonymous\" href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta.2/css/bootstrap.min.css\"\n" +
                "          integrity=\"sha384-PsH8R72JQ3SOdhVi3uxftmaW6Vc51MKb0q5P2rRUpPvrszuE4W1povHYgTpBfshb\" rel=\"stylesheet\">\n" +
                "</head>\n" +
                "<body style=\"min-height: 100vh;margin: 0 !important; padding: 0 !important;\n" +
                "background-color: white\">\n" +
                "<div class=\"row\" style=\"padding-top: 25px\">\n" +
                "    <div class=\"card col-xs-12 offset-xs-0 col-md-4 offset-md-4\">\n" +
                "        <div class=\"card-body\">\n" +
                "            <div>\n" +
                "                <h1 class=\"card-title\" style=\"padding-left: 10px;\">AES - Verify Phone Number</h1>\n" +
                "                <img src=\"https://img.icons8.com/ios-filled/90/4a90e2/one-time-password.png\"\n" +
                "                     style=\"padding-left: 10px;\" alt=\"one-time-password\"/>\n" +
                "            </div>\n" +
                "            <div>\n" +
                "                <p style=\"color: #000000 !important; padding-left: 10px;\"><b th:text=\"${user_first_name}\"></b>, please\n" +
                "                    use the\n" +
                "                    following\n" +
                "                    OTP to verify your phone number.</p>\n" +
                "                <p style=\"color: #000000 !important; padding-left: 10px;\">\n" +
                "                    Your OTP: <b th:text=\"${otp}\"></b>\n" +
                "                </p>\n" +
                "                <p style=\"color: #000000 !important; padding-left: 10px;\"><i>Note</i>: OTP is valid for 30 seconds.\n" +
                "                </p>\n" +
                "\n" +
                "                <p style=\"color: #000000 !important; padding-left: 10px;\">\n" +
                "                    Best Regards,<br>\n" +
                "                    AES Team\n" +
                "                </p>\n" +
                "            </div>\n" +
                "        </div>\n" +
                "\n" +
                "    </div>\n" +
                "</div>\n" +
                "</body>\n" +
                "</html>\n" +
                "\n" +
                "\n" +
                "\n", context);
        logger.info("otpEmail.html template processed successfully");

        MimeMessage message = emailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
        helper.setFrom(NOREPLY_ADDRESS);
        helper.setTo(email);
        helper.setSubject("[AES] OTP");
        helper.setText(htmlBody, true);
        //helper.addInline("attachment.png", resourceFile);
        emailSender.send(message);
    }
}
