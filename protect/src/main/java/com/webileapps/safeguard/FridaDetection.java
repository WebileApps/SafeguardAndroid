package com.webileapps.safeguard;

import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.List;

public class FridaDetection {

    public boolean detectFridaServer() {
        List<String> suspiciousProcesses = Arrays.asList("frida", "gum-js-loop", "frida-agent", "frida-server");

        try {
            File[] files = new File("/proc").listFiles();
            if (files == null) return false;

            for (File file : files) {
                if (file.getName().matches("\\d+")) {  // Check only PID directories
                    String cmdline = new String(java.nio.file.Files.readAllBytes(new File("/proc/" + file.getName() + "/cmdline").toPath()));
                    for (String suspiciousProcess : suspiciousProcesses) {
                        if (cmdline.contains(suspiciousProcess)) {
                            Log.e("Security", "Frida detected: " + cmdline);
                            return true;
                        }
                    }
                }
            }
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean detectFridaPort() {
        try {
            Process process = Runtime.getRuntime().exec("netstat -an");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            return reader.lines().anyMatch(line -> line.contains("27042") || line.contains("frida"));
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean detectFridaLibrary() {
        try {
            String maps = new String(java.nio.file.Files.readAllBytes(new File("/proc/self/maps").toPath()));
            if (maps.contains("frida") || maps.contains("gum-js")) {
                Log.e("Security", "Frida detected in memory!");
                return true;
            }
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean detectFridaTracer() {
        try {
            List<String> statusLines = java.nio.file.Files.readAllLines(new File("/proc/self/status").toPath());
            for (String line : statusLines) {
                if (line.startsWith("TracerPid")) {
                    int tracerPid = Integer.parseInt(line.split("\t")[1].trim());
                    return tracerPid > 0;
                }
            }
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean detectFridaDebugging() {
        boolean fridaServer = detectFridaServer();
        boolean fridaPort = detectFridaPort();
        boolean fridaLibrary = detectFridaLibrary();
        boolean fridaTracer = detectFridaTracer();

        boolean detected = fridaServer || fridaPort || fridaLibrary || fridaTracer;
        Log.e("Security>>>", "Frida detection result: Server=" + fridaServer + ", Port=" + fridaPort + ", Library=" + fridaLibrary + ", Tracer=" + fridaTracer);

        return detected;
    }
}
