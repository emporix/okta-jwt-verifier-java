package com.okta.jwt.impl.jjwt;

import java.util.function.Consumer;

public class ValidationResponse {

    private boolean valid = true;
    private String message;
    private Exception exception;

    ValidationResponse() {}

    public boolean isValid() {
        return valid;
    }

    public String getMessage() {
        return message;
    }

    public ValidationResponse setMessage(String message) {
        this.message = message;
        this.valid = false;
        return this;
    }

    public void ifInvalidThrow() {
        ifInvalid(res -> {
            throw new IllegalArgumentException(message, exception);
        });
    }

    public void ifInvalid(Consumer<ValidationResponse> consumer) {
        if (!valid) {
            consumer.accept(this);
        }
    }

    public Exception getException() {
        return exception;
    }

    public ValidationResponse setException(Exception exception) {
        this.exception = exception;
        return this;
    }

    static ValidationResponse valid() {
        return new ValidationResponse();
    }
}
