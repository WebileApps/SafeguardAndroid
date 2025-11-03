package com.webileapps.safeguard;

public interface IntegrityTokenListener {
    public void onIntegrityTokenSuccess(String token,String nonce);
    public void onIntegrityTokenFailure(Exception exception);
}
