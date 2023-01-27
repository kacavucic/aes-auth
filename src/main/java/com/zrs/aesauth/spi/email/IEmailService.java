package com.zrs.aesauth.spi.email;


import javax.mail.MessagingException;

public interface IEmailService {

    void sendOTPEmail(String firstName, String otp, String email) throws MessagingException;
    void sendVerifyPhoneNumberEmail(String firstName, String otp, String email) throws MessagingException;
}