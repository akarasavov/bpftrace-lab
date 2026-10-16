package com.neo4j.build;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Interactive page-cache monitor for Lucene indexes.
 *
 * Each index is a folder. Monitoring an index attaches a {@code bpftrace} program to the
 * kernel {@code filemap} tracepoints and scopes events to the folder by the set of inode
 * numbers of the files inside it, so only page-cache activity for that index is counted.
 *
 * <p>Tracepoints used:
 * <ul>
 *   <li>{@code filemap:mm_filemap_add_to_page_cache} — a page was loaded into the cache</li>
 *   <li>{@code filemap:mm_filemap_delete_from_page_cache} — a page was evicted</li>
 * </ul>
 *
 * <p>Requires Linux and root privileges (bpftrace). Run the whole tool with {@code sudo} so
 * that switching indexes can cleanly terminate the child bpftrace process.
 *
 * <p>Standalone CLI. Run it as its own tool (as root on Linux):
 * <pre>
 *   sudo java -cp ... com.neo4j.build.PageCacheMonitor [name]
 * </pre>
 * where an optional {@code name} starts monitoring that index immediately.
 *
 * <p>REPL commands:
 * <pre>
 *   monitor &lt;name&gt;   stop monitoring the current index (if any) and start on &lt;name&gt;
 *   stop            stop monitoring
 *   status          show what is being monitored
 *   help            show commands
 *   quit / exit     leave the monitor
 * </pre>
 */
public class PageCacheMonitor {

    /** Page size assumed for the KiB columns; matches x86_64 default. */
    private static final int PAGE_KIB = 4;

    /** Default folder that holds one sub-folder per index, overridable via {@code INDEX_ROOT}. */
    private static final Path DEFAULT_INDEX_ROOT = Path.of("indexes");

    private final Path indexRoot;
    private final String bpftrace;

    /** Entry point for the standalone monitor tool. */
    public static void main(String[] args) {
        String rootOverride = System.getenv("INDEX_ROOT");
        Path root = (rootOverride == null || rootOverride.isBlank())
                ? DEFAULT_INDEX_ROOT : Path.of(rootOverride);
        String initial = args.length >= 1 ? args[0] : null;
        new PageCacheMonitor(root).runInteractive(initial);
    }

    private Process current;
    private String currentIndex;
    private Path currentScript;

    public PageCacheMonitor(Path indexRoot) {
        this.indexRoot = indexRoot;
        String override = System.getenv("BPFTRACE");
        this.bpftrace = (override == null || override.isBlank()) ? "bpftrace" : override;
    }

    /** Runs the interactive REPL. If {@code initialIndex} is non-null, starts on it immediately. */
    public void runInteractive(String initialIndex) {
        if (!isLinux()) {
            System.err.println("Page-cache monitoring requires Linux + bpftrace (kernel BPF).");
            System.err.println("Current OS: " + System.getProperty("os.name")
                    + " — start/switch commands will fail here.");
        }
        printHelp();
        if (initialIndex != null) {
            startMonitoring(initialIndex);
        }
        try (BufferedReader in = new BufferedReader(new InputStreamReader(System.in))) {
            String line;
            System.out.print("\nmonitor> ");
            while ((line = in.readLine()) != null) {
                if (!handleCommand(line.trim())) {
                    break;
                }
                System.out.print("\nmonitor> ");
            }
        } catch (IOException e) {
            System.err.println("Input error: " + e.getMessage());
        } finally {
            stopMonitoring();
        }
    }

    /** Handles one REPL command. Returns false when the loop should exit. */
    private boolean handleCommand(String line) {
        if (line.isEmpty()) {
            return true;
        }
        String[] parts = line.split("\\s+");
        switch (parts[0]) {
            case "monitor" -> {
                if (parts.length < 2) {
                    System.err.println("Usage: monitor <name>");
                } else {
                    startMonitoring(parts[1]);
                }
            }
            case "stop" -> stopMonitoring();
            case "status" -> printStatus();
            case "help" -> printHelp();
            case "quit", "exit" -> {
                return false;
            }
            default -> System.err.println("Unknown command: " + parts[0] + " (try 'help')");
        }
        return true;
    }

    /** Stops any running monitor and starts one for the given index. */
    private void startMonitoring(String name) {
        Path folder = resolveIndex(name);
        if (folder == null) {
            System.err.println("No such index folder: " + name);
            return;
        }
        stopMonitoring();

        Map<Long, Path> inodes = collectInodes(folder);
        if (inodes.isEmpty()) {
            System.err.println("Index '" + name + "' has no files to monitor: " + folder);
            return;
        }

        try {
            currentScript = writeScript(inodes);
        } catch (IOException e) {
            System.err.println("Could not write bpftrace script: " + e.getMessage());
            return;
        }

        printLegend(name, folder, inodes);

        ProcessBuilder pb = new ProcessBuilder(bpftrace, currentScript.toString());
        pb.redirectErrorStream(true);
        try {
            current = pb.start();
        } catch (IOException e) {
            System.err.println("Failed to launch '" + bpftrace + "': " + e.getMessage());
            System.err.println("Install bpftrace and run the tool as root (sudo).");
            current = null;
            return;
        }
        currentIndex = name;
        pipeOutput(current);
    }

    /** Stops the current monitor process, if any, and cleans up its script. */
    private void stopMonitoring() {
        if (current != null) {
            System.out.println("\nStopping monitor for '" + currentIndex + "'...");
            current.destroy();
            try {
                if (!current.waitFor(3, java.util.concurrent.TimeUnit.SECONDS)) {
                    current.destroyForcibly();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            current = null;
            currentIndex = null;
        }
        if (currentScript != null) {
            try {
                Files.deleteIfExists(currentScript);
            } catch (IOException ignored) {
                // best effort
            }
            currentScript = null;
        }
    }

    private void printStatus() {
        if (current != null && current.isAlive()) {
            System.out.println("Monitoring index '" + currentIndex + "' (pid "
                    + current.pid() + ").");
        } else {
            System.out.println("Not monitoring any index.");
        }
    }

    /** Streams the bpftrace child's output to the console on a daemon thread. */
    private void pipeOutput(Process process) {
        Thread t = new Thread(() -> {
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = r.readLine()) != null) {
                    System.out.println(line);
                }
            } catch (IOException ignored) {
                // stream closed on stop
            }
        }, "bpftrace-output");
        t.setDaemon(true);
        t.start();
    }

    /** Resolves an index name to a folder: prefer {@code <root>/<name>}, else a direct path. */
    private Path resolveIndex(String name) {
        Path underRoot = indexRoot.resolve(name);
        if (Files.isDirectory(underRoot)) {
            return underRoot;
        }
        Path direct = Path.of(name);
        if (Files.isDirectory(direct)) {
            return direct;
        }
        return null;
    }

    /** Maps every regular file in the folder to its inode number. */
    private Map<Long, Path> collectInodes(Path folder) {
        Map<Long, Path> inodes = new LinkedHashMap<>();
        try (Stream<Path> files = Files.walk(folder)) {
            files.filter(Files::isRegularFile).forEach(p -> {
                try {
                    Object ino = Files.getAttribute(p, "unix:ino");
                    if (ino instanceof Number n) {
                        inodes.put(n.longValue(), p);
                    }
                } catch (IOException | UnsupportedOperationException e) {
                    System.err.println("  (skipping " + p + ": " + e.getMessage() + ")");
                }
            });
        } catch (IOException e) {
            System.err.println("Could not scan folder: " + e.getMessage());
        }
        return inodes;
    }

    /** Prints the inode→file legend so the per-file summary at exit is readable. */
    private void printLegend(String name, Path folder, Map<Long, Path> inodes) {
        System.out.println("Monitoring index '" + name + "' at " + folder.toAbsolutePath());
        System.out.println("Files (inode -> name):");
        inodes.forEach((ino, path) ->
                System.out.printf("  %-12d %s%n", ino, path.getFileName()));
        System.out.println();
        System.out.println("time      load_pg  evict_pg  load_KiB  evict_KiB   (per interval)");
    }

    /** Classpath location of the bpftrace program template. */
    private static final String TEMPLATE_RESOURCE = "/pagecache.bt";

    /**
     * Loads the {@code pagecache.bt} template, injects the watched inode set and page size,
     * and writes the resulting program to a temp file that bpftrace can run.
     */
    private Path writeScript(Map<Long, Path> inodes) throws IOException {
        String template;
        try (InputStream in = PageCacheMonitor.class.getResourceAsStream(TEMPLATE_RESOURCE)) {
            if (in == null) {
                throw new IOException("Missing bpftrace template on classpath: " + TEMPLATE_RESOURCE);
            }
            template = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }

        String inodeInit = inodes.keySet().stream()
                .map(ino -> "@ino[" + ino + "] = 1;")
                .collect(Collectors.joining("\n  "));

        String program = template
                .replace("// __INODES__", inodeInit)
                .replace("__PAGE_KIB__", Integer.toString(PAGE_KIB));

        Path script = Files.createTempFile("pagecache-", ".bt");
        Files.writeString(script, program);
        return script;
    }

    private void printHelp() {
        System.out.println("""
                Page-cache monitor commands:
                  monitor <name>   switch monitoring to index <name> (a folder)
                  stop             stop monitoring
                  status           show current monitoring target
                  help             show this help
                  quit / exit      leave the monitor
                Columns per 1s interval: pages loaded / evicted and their size in KiB.""");
    }

    private static boolean isLinux() {
        return System.getProperty("os.name", "").toLowerCase().contains("linux");
    }
}
