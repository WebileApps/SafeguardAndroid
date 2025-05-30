package com.webileapps.safeguard;

import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
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
                String fileName = file.getName();

                // Avoid regex - check if name is numeric (PID)
                if (isNumeric(fileName)) {
                    FileInputStream fis = null;
                    try {
                        File cmdlineFile = new File("/proc/" + fileName + "/cmdline");
                        if (!cmdlineFile.exists()) continue;

                        fis = new FileInputStream(cmdlineFile);
                        byte[] data = new byte[fis.available()];
                        fis.read(data);

                        String cmdline = new String(data).trim();
                        for (String suspiciousProcess : suspiciousProcesses) {
                            if (cmdline.contains(suspiciousProcess)) {
                                Log.e("Security", "Frida detected: " + cmdline);
                                return true;
                            }
                        }
                    } catch (Exception e) {
                        // Likely a permissions issue; ignore
                    } finally {
                        if (fis != null) {
                            try { fis.close(); } catch (IOException ignored) {}
                        }
                    }
                }
            }
        } catch (Exception ignored) {

        }
        return false;
    }

    private boolean isNumeric(String str) {
        if (str == null || str.isEmpty()) return false;
        for (int i = 0; i < str.length(); i++) {
            if (!Character.isDigit(str.charAt(i))) return false;
        }
        return true;
    }

    public boolean detectFridaPort() {
        try {
            Process process = Runtime.getRuntime().exec("netstat -an");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            return reader.lines().anyMatch(line -> line.contains("27042") || line.contains("frida"));
        } catch (Exception e) {

            return false;
        }
    }

    public boolean detectFridaLibrary() {
        try {
            FileInputStream fis = null;
            try {
                fis = new FileInputStream(new File("/proc/self/maps"));
                byte[] data = new byte[fis.available()];
                fis.read(data);
                String maps = new String(data);
                if (maps.contains("frida") || maps.contains("gum-js")) {
                    Log.e("Security", "Frida detected in memory!");
                    return true;
                }
                return false;
            } catch (Exception e) {
                return false;
            } finally {
                if (fis != null) {
                    fis.close();
                }
            }
        } catch (Exception e) {
            return false;
        }
    }

    public boolean detectFridaTracer() {
        try {
            FileInputStream fis = null;
            try {
                fis = new FileInputStream(new File("/proc/self/status"));
                byte[] data = new byte[fis.available()];
                fis.read(data);
                String status = new String(data);
                String[] statusLines = status.split("\n");
                for (String line : statusLines) {
                    if (line.startsWith("TracerPid")) {
                        int tracerPid = Integer.parseInt(line.split("\t")[1].trim());
                        return tracerPid > 0;
                    }
                }
                return false;
            } catch (Exception e) {
                return false;
            } finally {
                if (fis != null) {
                    fis.close();
                }
            }
        } catch (Exception e) {
            return false;
        }
    }

    public boolean detectFridaDebugging() {
        boolean fridaServer = detectFridaServer();
        boolean fridaPort = detectFridaPort();
        boolean fridaLibrary = detectFridaLibrary();
        boolean fridaTracer = detectFridaTracer();

        boolean detected = fridaServer || fridaPort || fridaLibrary || fridaTracer;
        if (detected) {
            Log.e("Security>>>", "Frida detection result: Server=" + fridaServer + ", Port=" + fridaPort + ", Library=" + fridaLibrary + ", Tracer=" + fridaTracer);
        }

        return detected;
    }
}
