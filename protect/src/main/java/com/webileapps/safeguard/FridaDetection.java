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
        FileInputStream fis = null;
        try {
            fis = new FileInputStream("/proc/" + pid + "/cmdline");
            byte[] data = new byte[fis.available()];
            fis.read(data);
            String cmdline = new String(data).trim().toLowerCase();

            for (String process : SUSPICIOUS_PROCESSES) {
                if (cmdline.contains(process)) {
                    return true;
                }
            }
        } catch (Exception e) {
            // Ignore
        } finally {
            try {
                if (fis != null) fis.close();
            } catch (IOException e) {
                // Ignore
            }
        }
        return false;
    }

    private boolean checkProcessComm(String pid) {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream("/proc/" + pid + "/comm");
            byte[] data = new byte[fis.available()];
            fis.read(data);
            String comm = new String(data).trim().toLowerCase();

            for (String process : SUSPICIOUS_PROCESSES) {
                if (comm.contains(process)) {
                    return true;
                }
            }
        } catch (Exception e) {
            // Ignore
        } finally {
            try {
                if (fis != null) fis.close();
            } catch (IOException e) {
                // Ignore
            }
        }
        return false;
    }

    private boolean checkProcessStat(String pid) {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream("/proc/" + pid + "/stat");
            byte[] data = new byte[fis.available()];
            fis.read(data);
            String stat = new String(data).trim().toLowerCase();

            for (String process : SUSPICIOUS_PROCESSES) {
                if (stat.contains(process)) {
                    return true;
                }
            }
        } catch (Exception e) {
            // Ignore
        } finally {
            try {
                if (fis != null) fis.close();
            } catch (IOException e) {
                // Ignore
            }
        }
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
        Process process = null;
        BufferedReader reader = null;
        try {
            process = Runtime.getRuntime().exec("netstat -an");
            reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("27042") || line.contains("27043") ||
                        line.contains("27044") || line.contains("27045") ||
                        line.toLowerCase().contains("frida")) {
                    return true;
                }
            }
        } catch (Exception e) {
            Log.d(TAG, "Error in netstat detection", e);
        } finally {
            try {
                if (reader != null) reader.close();
                if (process != null) process.destroy();
            } catch (Exception e) {
                // Ignore
            }
        }
        return false;
    }

    private boolean detectFridaPortTcp() {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream("/proc/net/tcp");
            byte[] data = new byte[fis.available()];
            fis.read(data);
            String tcp = new String(data);

            // Convert port numbers to hex and check
            for (int port : FRIDA_PORTS) {
                String hexPort = String.format("%04X", port);
                if (tcp.contains(hexPort)) {
                    return true;
                }
            }
        } catch (Exception e) {
            Log.d(TAG, "Error checking TCP ports", e);
        } finally {
            try {
                if (fis != null) fis.close();
            } catch (IOException e) {
                // Ignore
            }
        }
        return false;
    }

    private boolean testFridaPortConnections() {
        for (int port : FRIDA_PORTS) {
            Socket socket = null;
            try {
                socket = new Socket();
                socket.connect(new InetSocketAddress("127.0.0.1", port), 100);
                return true; // Port is open
            } catch (Exception e) {
                // Continue to next port
            } finally {
                try {
                    if (socket != null) socket.close();
                } catch (IOException e) {
                    // Ignore
                }
            }
        }
        return false;
    }

    // Enhanced library detection
    public boolean detectFridaLibrary() {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream("/proc/self/maps");
            byte[] data = new byte[fis.available()];
            fis.read(data);
            String maps = new String(data).toLowerCase();

            for (String library : SUSPICIOUS_LIBRARIES) {
                if (maps.contains(library)) {
                    return true;
                }
            }
        } catch (Exception e) {
            Log.d(TAG, "Error checking libraries", e);
        } finally {
            try {
                if (fis != null) fis.close();
            } catch (IOException e) {
                // Ignore
            }
        }
        return false;
    }

    // Enhanced tracer detection
    public boolean detectFridaTracer() {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream("/proc/self/status");
            byte[] data = new byte[fis.available()];
            fis.read(data);
            String status = new String(data);

            String[] lines = status.split("\n");
            for (String line : lines) {
                if (line.startsWith("TracerPid")) {
                    String[] parts = line.split("\\s+");
                    if (parts.length >= 2) {
                        int tracerPid = Integer.parseInt(parts[1]);
                        if (tracerPid > 0) {
                            // Check if tracer is Frida
                            return isTracerFrida(tracerPid);
                        }
                    }
                }
            }
        } catch (Exception e) {
            Log.d(TAG, "Error checking tracer", e);
        } finally {
            try {
                if (fis != null) fis.close();
            } catch (IOException e) {
                // Ignore
            }
        }
        return false;
    }

    private boolean isTracerFrida(int tracerPid) {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream("/proc/" + tracerPid + "/cmdline");
            byte[] data = new byte[fis.available()];
            fis.read(data);
            String cmdline = new String(data).toLowerCase();

            for (String process : SUSPICIOUS_PROCESSES) {
                if (cmdline.contains(process)) {
                    return true;
                }
            }
        } catch (Exception e) {
            // If we can't check, assume it's suspicious
            return true;
        } finally {
            try {
                if (fis != null) fis.close();
            } catch (IOException e) {
                // Ignore
            }
        }
        return false;
    }

    // New detection methods
    public boolean detectFridaThreads() {
        try {
            File taskDir = new File("/proc/self/task");
            File[] tasks = taskDir.listFiles();
            if (tasks == null) return false;

            for (File task : tasks) {
                if (!isNumeric(task.getName())) continue;

                FileInputStream commFis = null;
                try {
                    commFis = new FileInputStream("/proc/self/task/" + task.getName() + "/comm");
                    byte[] data = new byte[commFis.available()];
                    commFis.read(data);
                    String threadName = new String(data).trim().toLowerCase();

                    for (String fridaThread : FRIDA_THREADS) {
                        if (threadName.contains(fridaThread)) {
                            return true;
                        }
                    }
                } catch (Exception e) {
                    // Continue to next task
                } finally {
                    try {
                        if (commFis != null) commFis.close();
                    } catch (IOException e) {
                        // Ignore
                    }
                }
            }
        } catch (Exception e) {
            Log.d(TAG, "Error checking threads", e);
        }
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
                } catch (UnsatisfiedLinkError e) {
                    // Continue to next library
                }
            }
        } catch (Exception e) {
            Log.d(TAG, "Error checking native libraries", e);
        }
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
        } catch (Exception e) {
            Log.d(TAG, "Error checking environment variables", e);
        }
        return false;
    }

    public boolean detectFridaTcpConnections() {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream("/proc/net/tcp");
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
        } catch (Exception e) {
            Log.d(TAG, "Error checking TCP connections", e);
        } finally {
            try {
                if (fis != null) fis.close();
            } catch (IOException e) {
                // Ignore
            }
        }
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
                    } catch (Exception e) {
                        // Continue
                    }
                }
            }
        } catch (Exception e) {
            Log.d(TAG, "Error checking JNI hooks", e);
        }
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
                } catch (ClassNotFoundException e) {
                    // Continue
                }
            }

            // Check stack trace for Xposed
            StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
            for (StackTraceElement element : stackTrace) {
                if (element.getClassName().contains("de.robv.android.xposed")) {
                    return true;
                }
            }

        } catch (Exception e) {
            Log.d(TAG, "Error checking Xposed", e);
        }
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
        } catch (Exception e) {
            Log.d(TAG, "Kill method 1 failed", e);
        }
    }

    private void killAppMethod2() {
        try {
            android.os.Process.killProcess(android.os.Process.myPid());
        } catch (Exception e) {
            Log.d(TAG, "Kill method 2 failed", e);
        }
    }

    private void killAppMethod3() {
        try {
            System.exit(0);
        } catch (Exception e) {
            Log.d(TAG, "Kill method 3 failed", e);
        }
    }

    // Initialize detection with automatic kill
    public void initializeProtection() {
        executorService.execute(new Runnable() {
            @Override
            public void run() {
                if (detectFridaDebugging() || isXposedPresent()) {
                    killApplication("Security threat detected during initialization");
                }
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
        } catch (Exception e) {
            Log.d(TAG, "Error checking app tampering", e);
        }
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
            try {
                if (new File(path).exists()) {
                    return true;
                }
            } catch (SecurityException e) {
                Log.d(TAG, "Security exception checking root path: " + path);
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