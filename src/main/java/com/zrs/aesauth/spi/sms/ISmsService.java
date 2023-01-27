package com.zrs.aesauth.spi.sms;

import java.util.Map;

public interface ISmsService {

    void sendOTPSms(String firstName, String otp, String phoneNumber);
    void sendVerifyPhoneNumberSms(String firstName, String otp, String phoneNumber);
}