package com.webileapps.safeguard.retrofit;

import java.util.concurrent.TimeUnit;

import okhttp3.OkHttpClient;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;

public class RetrofitClient {

    private static final String BASE_URL = "https://cug.canararobeco.com/verify-integrity/";

    private static Retrofit retrofit;
    private static ApiService apiService;

    // Private constructor — prevents instantiation
    public RetrofitClient() { }

    public static ApiService getApi(String url) {
        if (apiService == null) {

            OkHttpClient okHttp = new OkHttpClient.Builder()
                    .connectTimeout(30, TimeUnit.SECONDS)
                    .readTimeout(30, TimeUnit.SECONDS)
                    .writeTimeout(30, TimeUnit.SECONDS)
                    .build();

            retrofit = new Retrofit.Builder()
                    .baseUrl(url)
                    .client(okHttp)
                    .addConverterFactory(GsonConverterFactory.create())
                    .build();

            apiService = retrofit.create(ApiService.class);
        }

        return apiService;
    }
}

