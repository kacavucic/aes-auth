package com.zrs.aesauth.spi.sms;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class SmsServiceImpl implements ISmsService {

    @Value("${sms.TWILIO_ACCOUNT_SID}")
    private String sid;

    @Value("${sms.TWILIO_AUTH_TOKEN}")
    private String token;

    public SmsServiceImpl() {
    }

    @Override
    public void sendOTPSms(String firstName, String otp, String phoneNumber) {

        Twilio.init(sid, token);
        String message =
                firstName + ", your OTP is " + otp;
        Message.creator(new PhoneNumber(phoneNumber),
                new PhoneNumber("+16294682658"), message).create();
    }

    @Override
    public void sendVerifyPhoneNumberSms(String firstName, String otp, String phoneNumber) {
        Twilio.init(sid, token);
        String message =
                firstName + ", your OTP is " + otp;
        Message.creator(new PhoneNumber(phoneNumber),
                new PhoneNumber("+16294682658"), message).create();
    }
}
