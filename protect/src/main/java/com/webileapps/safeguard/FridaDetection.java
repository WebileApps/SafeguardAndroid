package com.webileapps.safeguard;

import android.app.Activity;
import android.content.Context;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class FridaDetection {
    private static final String TAG = "FridaDetection";
    private Context context;
    private ExecutorService executorService;
    private boolean continuousMonitoring = false;

    // Common Frida-related strings and processes
    private static final List<String> SUSPICIOUS_PROCESSES = Arrays.asList(
            "frida", "frida-server", "frida-agent", "gum-js-loop",
            "frida-portal", "frida-helper", "re.frida.server"
    );

    private static final List<String> SUSPICIOUS_LIBRARIES = Arrays.asList(
            "frida", "gum-js", "frida-agent", "frida-gadget",
            "libfrida", "libgum", "frida-core"
    );

    private static final List<String> FRIDA_THREADS = Arrays.asList(
            "gmain", "gdbus", "gum-js-loop", "pool-frida"
    );

    // Default Frida ports
    private static final int[] FRIDA_PORTS = {27042, 27043, 27044, 27045};

    public FridaDetection(Context context) {
        this.context = context;
        this.executorService = Executors.newCachedThreadPool();
    }


    // Main detection method that combines all checks
    public boolean detectFridaDebugging() {
        boolean fridaServer = detectFridaServer();
        boolean fridaPort = detectFridaPorts();
        boolean fridaLibrary = detectFridaLibrary();
        boolean fridaTracer = detectFridaTracer();
        boolean fridaThreads = detectFridaThreads();
        boolean fridaNative = detectFridaNativeLibraries();
        boolean fridaEnvironment = detectFridaEnvironmentVariables();
        boolean fridaTcp = detectFridaTcpConnections();
        boolean jniHooks = detectJNIHooks();

        boolean detected = fridaServer || fridaPort || fridaLibrary || fridaTracer ||
                fridaThreads || fridaNative || fridaEnvironment || fridaTcp || jniHooks;

        if (detected) {
            Log.e(TAG, "Frida detection result: Server=" + fridaServer +
                    ", Port=" + fridaPort + ", Library=" + fridaLibrary +
                    ", Tracer=" + fridaTracer + ", Threads=" + fridaThreads +
                    ", Native=" + fridaNative + ", Environment=" + fridaEnvironment +
                    ", TCP=" + fridaTcp + ", JNI=" + jniHooks);
        }

        return detected;
    }

    // Enhanced process detection
    public boolean detectFridaServer() {
        try {
            File procDir = new File("/proc");
            File[] files = procDir.listFiles();
            if (files == null) return false;

            for (File file : files) {
                if (!file.isDirectory() || !isNumeric(file.getName())) continue;

                // Check cmdline
                if (checkProcessCmdline(file.getName())) return true;

                // Check comm (process name)
                if (checkProcessComm(file.getName())) return true;

                // Check stat
                if (checkProcessStat(file.getName())) return true;
            }
        } catch (Exception e) {
            Log.d(TAG, "Process detection failed: " + e.getMessage());
        }
        return false;
    }

    private boolean checkProcessCmdline(String pid) {
        try (FileInputStream fis = new FileInputStream("/proc/" + pid + "/cmdline")) {
            byte[] data = new byte[fis.available()];
            fis.read(data);
            String cmdline = new String(data).trim().toLowerCase();

            return SUSPICIOUS_PROCESSES.stream().anyMatch(cmdline::contains);
        } catch (Exception ignored) {}
        return false;
    }


    private boolean checkProcessComm(String pid) {
        try (FileInputStream fis = new FileInputStream("/proc/" + pid + "/comm")) {
            byte[] data = new byte[fis.available()];
            fis.read(data);
            String comm = new String(data).trim().toLowerCase();

            return SUSPICIOUS_PROCESSES.stream().anyMatch(comm::contains);
        } catch (Exception ignored) {}
        return false;
    }

    private boolean checkProcessStat(String pid) {
        try (FileInputStream fis = new FileInputStream("/proc/" + pid + "/stat")) {
            byte[] data = new byte[fis.available()];
            fis.read(data);
            String stat = new String(data).trim().toLowerCase();

            return SUSPICIOUS_PROCESSES.stream().anyMatch(stat::contains);
        } catch (Exception ignored) {}
        return false;
    }
    // Enhanced port detection
    public boolean detectFridaPorts() {
        // Check netstat
        if (detectFridaPortNetstat()) return true;

        // Check /proc/net/tcp
        if (detectFridaPortTcp()) return true;

        // Direct socket connection test
        return testFridaPortConnections();
    }

    private boolean detectFridaPortNetstat() {
        try {
            Process process = Runtime.getRuntime().exec("netstat -an");
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                return reader.lines().anyMatch(line ->
                        line.contains("27042") || line.contains("27043") ||
                                line.contains("27044") || line.contains("27045") ||
                                line.toLowerCase().contains("frida")
                );
            }
        } catch (Exception ignored) {}
        return false;
    }

    private boolean detectFridaPortTcp() {
        try (FileInputStream fis = new FileInputStream("/proc/net/tcp")) {
            byte[] data = new byte[fis.available()];
            fis.read(data);
            String tcp = new String(data);

            // Convert port numbers to hex and check
            for (int port : FRIDA_PORTS) {
                String hexPort = String.format("%04X", port);
                if (tcp.contains(hexPort)) return true;
            }
        } catch (Exception ignored) {}
        return false;
    }

    private boolean testFridaPortConnections() {
        for (int port : FRIDA_PORTS) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress("127.0.0.1", port), 100);
                return true; // Port is open
            } catch (Exception ignored) {}
        }
        return false;
    }

    // Enhanced library detection
    public boolean detectFridaLibrary() {
        try (FileInputStream fis = new FileInputStream("/proc/self/maps")) {
            byte[] data = new byte[fis.available()];
            fis.read(data);
            String maps = new String(data).toLowerCase();

            return SUSPICIOUS_LIBRARIES.stream().anyMatch(maps::contains);
        } catch (Exception ignored) {}
        return false;
    }

    // Enhanced tracer detection
    public boolean detectFridaTracer() {
        try (FileInputStream fis = new FileInputStream("/proc/self/status")) {
            byte[] data = new byte[fis.available()];
            fis.read(data);
            String status = new String(data);

            for (String line : status.split("\n")) {
                if (line.startsWith("TracerPid")) {
                    int tracerPid = Integer.parseInt(line.split("\\s+")[1]);
                    if (tracerPid > 0) {
                        // Check if tracer is Frida
                        return isTracerFrida(tracerPid);
                    }
                }
            }
        } catch (Exception ignored) {}
        return false;
    }

    private boolean isTracerFrida(int tracerPid) {
        try (FileInputStream fis = new FileInputStream("/proc/" + tracerPid + "/cmdline")) {
            byte[] data = new byte[fis.available()];
            fis.read(data);
            String cmdline = new String(data).toLowerCase();
            return SUSPICIOUS_PROCESSES.stream().anyMatch(cmdline::contains);
        } catch (Exception ignored) {}
        return true; // If we can't check, assume it's suspicious
    }

    // New detection methods
    public boolean detectFridaThreads() {
        try (FileInputStream fis = new FileInputStream("/proc/self/task")) {
            File taskDir = new File("/proc/self/task");
            File[] tasks = taskDir.listFiles();
            if (tasks == null) return false;

            for (File task : tasks) {
                if (!isNumeric(task.getName())) continue;

                try (FileInputStream commFis = new FileInputStream("/proc/self/task/" + task.getName() + "/comm")) {
                    byte[] data = new byte[commFis.available()];
                    commFis.read(data);
                    String threadName = new String(data).trim().toLowerCase();

                    if (FRIDA_THREADS.stream().anyMatch(threadName::contains)) {
                        return true;
                    }
                } catch (Exception ignored) {}
            }
        } catch (Exception ignored) {}
        return false;
    }

    public boolean detectFridaNativeLibraries() {
        try {
            // Check loaded libraries using System.mapLibraryName
            String[] libNames = {"frida", "gum", "frida-agent", "frida-gadget"};
            for (String libName : libNames) {
                try {
                    System.loadLibrary(libName);
                    return true; // If it loads, it exists
                } catch (UnsatisfiedLinkError ignored) {}
            }
        } catch (Exception ignored) {}
        return false;
    }

    public boolean detectFridaEnvironmentVariables() {
        try {
            String[] envVars = {"FRIDA_AGENT", "FRIDA_GADGET", "FRIDA_OPTIONS"};
            for (String envVar : envVars) {
                if (System.getenv(envVar) != null) {
                    return true;
                }
            }
        } catch (Exception ignored) {}
        return false;
    }

    public boolean detectFridaTcpConnections() {
        try (FileInputStream fis = new FileInputStream("/proc/net/tcp")) {
            byte[] data = new byte[fis.available()];
            fis.read(data);
            String tcpData = new String(data);

            // Look for established connections to common Frida ports
            String[] lines = tcpData.split("\n");
            for (String line : lines) {
                String[] parts = line.trim().split("\\s+");
                if (parts.length > 3 && "01".equals(parts[3])) { // ESTABLISHED
                    String remoteAddress = parts[2];
                    if (remoteAddress.contains("699A") || // 27042 in hex
                            remoteAddress.contains("699B") || // 27043 in hex
                            remoteAddress.contains("699C") || // 27044 in hex
                            remoteAddress.contains("699D")) { // 27045 in hex
                        return true;
                    }
                }
            }
        } catch (Exception ignored) {}
        return false;
    }

    public boolean detectJNIHooks() {
        try {
            // Check for common JNI function hooks
            Class<?> vmDebug = Class.forName("dalvik.system.VMDebug");
            Method[] methods = vmDebug.getDeclaredMethods();

            for (Method method : methods) {
                if (method.getName().contains("isDebuggerConnected") ||
                        method.getName().contains("getLoadedClasses")) {
                    // These methods are commonly hooked by Frida
                    try {
                        Object result = method.invoke(null);
                        // If method behavior seems modified, it might be hooked
                        if (result != null && detectAnomalousJNIBehavior(method, result)) {
                            return true;
                        }
                    } catch (Exception ignored) {}
                }
            }
        } catch (Exception ignored) {}
        return false;
    }

    private boolean detectAnomalousJNIBehavior(Method method, Object result) {
        // Implementation depends on specific behavior you want to detect
        // This is a placeholder for detecting anomalous behavior
        return false;
    }

    // Xposed detection (enhanced)
    public static boolean isXposedPresent() {
        try {
            // Check for Xposed classes
            String[] xposedClasses = {
                    "de.robv.android.xposed.XposedHelpers",
                    "de.robv.android.xposed.XposedBridge",
                    "de.robv.android.xposed.XC_MethodHook"
            };

            for (String className : xposedClasses) {
                try {
                    Class.forName(className);
                    return true;
                } catch (ClassNotFoundException ignored) {}
            }

            // Check stack trace for Xposed
            StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
            for (StackTraceElement element : stackTrace) {
                if (element.getClassName().contains("de.robv.android.xposed")) {
                    return true;
                }
            }

        } catch (Exception ignored) {}
        return false;
    }

    // Utility methods
    private boolean isNumeric(String str) {
        if (str == null || str.isEmpty()) return false;
        for (int i = 0; i < str.length(); i++) {
            if (!Character.isDigit(str.charAt(i))) return false;
        }
        return true;
    }

    // Continuous monitoring
    public void startContinuousMonitoring(int intervalMs) {
        continuousMonitoring = true;
        Handler handler = new Handler(Looper.getMainLooper());

        Runnable monitoringTask = new Runnable() {
            @Override
            public void run() {
                if (continuousMonitoring && detectFridaDebugging()) {
                    killApplication("Frida detected during continuous monitoring");
                }

                if (continuousMonitoring) {
                    handler.postDelayed(this, intervalMs);
                }
            }
        };

        handler.post(monitoringTask);
    }

    public void stopContinuousMonitoring() {
        continuousMonitoring = false;
    }

    // Kill application methods
    public void killApplication(String reason) {
        Log.e(TAG, "Killing application: " + reason);

        // Multiple ways to kill the app
        killAppMethod1();
        killAppMethod2();
        killAppMethod3();
    }

    private void killAppMethod1() {
        try {
            if (context instanceof Activity) {
                ((Activity) context).finishAffinity();
            }
        } catch (Exception ignored) {}
    }

    private void killAppMethod2() {
        try {
            android.os.Process.killProcess(android.os.Process.myPid());
        } catch (Exception ignored) {}
    }

    private void killAppMethod3() {
        try {
            System.exit(0);
        } catch (Exception ignored) {}
    }

    // Initialize detection with automatic kill
    public void initializeProtection() {
        executorService.execute(() -> {
            if (detectFridaDebugging() || isXposedPresent()) {
                killApplication("Security threat detected during initialization");
            }
        });
    }

    // Advanced anti-tampering
    public boolean isAppTampered() {
        try {
            // Check if debugging is enabled
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
                if (android.os.Debug.isDebuggerConnected()) {
                    return true;
                }
            }

            // Check for root
            return isDeviceRooted();
        } catch (Exception ignored) {}
        return false;
    }

    private boolean isDeviceRooted() {
        String[] rootIndicators = {
                "/system/app/Superuser.apk",
                "/sbin/su", "/system/bin/su", "/system/xbin/su",
                "/data/local/xbin/su", "/data/local/bin/su",
                "/system/sd/xbin/su", "/system/bin/failsafe/su",
                "/data/local/su", "/su/bin/su"
        };

        for (String path : rootIndicators) {
            if (new File(path).exists()) {
                return true;
            }
        }

        return false;
    }

    public void cleanup() {
        stopContinuousMonitoring();
        if (executorService != null && !executorService.isShutdown()) {
            executorService.shutdown();
        }
    }
}
