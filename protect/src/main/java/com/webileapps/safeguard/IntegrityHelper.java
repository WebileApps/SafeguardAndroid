package com.webileapps.safeguard;

import android.content.Context;
import android.util.Base64;

import com.google.android.play.core.integrity.IntegrityManager;
import com.google.android.play.core.integrity.IntegrityManagerFactory;
import com.google.android.play.core.integrity.IntegrityTokenRequest;

import java.security.SecureRandom;

public class IntegrityHelper {

    private final Context context;
    private final IntegrityManager integrityManager;

    public interface IntegrityCallback {
        void onResult(String token, Exception error);
    }

    public IntegrityHelper(Context context) {
        this.context = context;
        this.integrityManager = IntegrityManagerFactory.create(context);
    }

    public void requestIntegrity(IntegrityCallback callback) {
        String nonce = generateNonce();

        IntegrityTokenRequest request = IntegrityTokenRequest.builder()
                .setNonce(nonce)
                .build();

        integrityManager.requestIntegrityToken(request)
                .addOnSuccessListener(response -> {
                    String integrityToken = response.token();
                    callback.onResult(integrityToken, null);
                })
                .addOnFailureListener(exception -> {
                    callback.onResult(null, exception);
                });
    }

    private String generateNonce() {
        byte[] randomBytes = new byte[32];
        new SecureRandom().nextBytes(randomBytes);
        return Base64.encodeToString(randomBytes, Base64.URL_SAFE | Base64.NO_WRAP);
    }
}
