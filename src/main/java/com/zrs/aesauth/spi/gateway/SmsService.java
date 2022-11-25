package com.zrs.aesauth.spi.gateway;

public interface SmsService {

    void send(String phoneNumber, String message);

}
