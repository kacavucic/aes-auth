package com.zrs.aesauth.spi.sms;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import org.springframework.stereotype.Service;

@Service
public class SmsServiceImpl implements ISmsService {


    private String sid;

    private String token;

    public SmsServiceImpl() {
        this.sid = System.getenv("TWILIO_ACCOUNT_SID");
        this.token = System.getenv("TWILIO_ACCOUNT_TOKEN");
    }

    @Override
    public void sendOTPSms(String firstName, String otp, String phoneNumber) {

        Twilio.init(sid, token);
        String message =
                firstName + ", your OTP is " + otp;
        Message.creator(new PhoneNumber(phoneNumber),
                new PhoneNumber("+12544428507"), message).create();
    }

    @Override
    public void sendVerifyPhoneNumberSms(String firstName, String otp, String phoneNumber) {
        Twilio.init(sid, token);
        String message =
                firstName + ", your OTP is " + otp;
        Message.creator(new PhoneNumber(phoneNumber),
                new PhoneNumber("+12544428507"), message).create();
    }
}
