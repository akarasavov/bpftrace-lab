package com.neo4j.build;

import org.apache.lucene.document.Document;
import org.apache.lucene.document.KnnFloatVectorField;
import org.apache.lucene.document.StoredField;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.index.VectorSimilarityFunction;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.KnnFloatVectorQuery;
import org.apache.lucene.search.ScoreDoc;
import org.apache.lucene.search.TopDocs;
import org.apache.lucene.store.FSDirectory;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Random;

/**
 * Interactive command line tool for a Lucene HNSW vector index on disk.
 *
 * Runs a single long-lived JVM (one stable PID for external profiling such as
 * bpftrace) and reads commands from standard input, one per line:
 *   create <name>            create an empty index with the given name
 *   insert <name> <n>        insert n random vectors into the index
 *   search <name> <k>        find the top k neighbours of a random query vector
 *   pid                      print this process's PID
 *   help                     show the available commands
 *   exit | quit              leave the tool
 */
public class IndexManager {

    private static final int DIMENSIONS = 128;
    private static final String VECTOR_FIELD = "vector";
    private static final String ID_FIELD = "id";
    private static final Path INDEX_ROOT = Path.of("indexes");

    public static void main(String[] args) throws Exception {
        long pid = ProcessHandle.current().pid();
        System.out.println("Lucene vector index manager (interactive). PID=" + pid);
        usage();

        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String line;
        System.out.print("> ");
        while ((line = in.readLine()) != null) {
            String[] tokens = line.trim().split("\\s+");
            if (tokens.length == 0 || tokens[0].isEmpty()) {
                System.out.print("> ");
                continue;
            }
            try {
                if (!dispatch(tokens)) {
                    break;
                }
            } catch (Exception e) {
                System.err.println("Error: " + e.getMessage());
            }
            System.out.print("> ");
        }
        System.out.println("Bye.");
    }

    /** Runs one command. Returns false when the loop should stop. */
    private static boolean dispatch(String[] args) throws Exception {
        String command = args[0];
        switch (command) {
            case "create" -> {
                requireArgs(args, 2, "create <name>");
                create(args[1]);
            }
            case "insert" -> {
                requireArgs(args, 3, "insert <name> <n>");
                insert(args[1], Integer.parseInt(args[2]));
            }
            case "search" -> {
                requireArgs(args, 3, "search <name> <k>");
                search(args[1], Integer.parseInt(args[2]));
            }
            case "pid" -> System.out.println("PID=" + ProcessHandle.current().pid());
            case "help" -> usage();
            case "exit", "quit" -> {
                return false;
            }
            default -> {
                System.err.println("Unknown command: " + command);
                usage();
            }
        }
        return true;
    }

    private static void create(String name) throws Exception {
        Path indexPath = indexPath(name);
        if (Files.exists(indexPath)) {
            throw new IllegalStateException("Index already exists: " + indexPath.toAbsolutePath());
        }
        Files.createDirectories(indexPath);
        // Open a writer once to materialise an empty, valid index (segments file).
        try (FSDirectory directory = FSDirectory.open(indexPath);
             IndexWriter writer = new IndexWriter(directory, new IndexWriterConfig())) {
            writer.commit();
        }
        System.out.println("Created index '" + name + "' at " + indexPath.toAbsolutePath());
    }

    private static void insert(String name, int n) throws Exception {
        Path indexPath = requireExistingIndex(name);
        Random random = new Random();
        try (FSDirectory directory = FSDirectory.open(indexPath);
             IndexWriter writer = new IndexWriter(directory, new IndexWriterConfig())) {
            int base = countDocs(indexPath);
            for (int i = 0; i < n; i++) {
                Document doc = new Document();
                doc.add(new StoredField(ID_FIELD, base + i));
                doc.add(new KnnFloatVectorField(VECTOR_FIELD, randomVector(random),
                        VectorSimilarityFunction.COSINE));
                writer.addDocument(doc);
            }
            writer.commit();
        }
        System.out.println("Inserted " + n + " vectors into '" + name + "'");
    }

    private static void search(String name, int k) throws Exception {
        Path indexPath = requireExistingIndex(name);
        Random random = new Random();
        float[] query = randomVector(random);
        try (FSDirectory directory = FSDirectory.open(indexPath);
             DirectoryReader reader = DirectoryReader.open(directory)) {
            IndexSearcher searcher = new IndexSearcher(reader);
            TopDocs topDocs = searcher.search(
                    new KnnFloatVectorQuery(VECTOR_FIELD, query, k), k);

            System.out.println("Top " + k + " neighbours in '" + name + "':");
            for (ScoreDoc scoreDoc : topDocs.scoreDocs) {
                Document doc = searcher.storedFields().document(scoreDoc.doc);
                System.out.println("  id=" + doc.getField(ID_FIELD).numericValue()
                        + " score=" + scoreDoc.score);
            }
        }
    }

    private static int countDocs(Path indexPath) throws Exception {
        try (FSDirectory directory = FSDirectory.open(indexPath);
             DirectoryReader reader = DirectoryReader.open(directory)) {
            return reader.numDocs();
        }
    }

    private static Path indexPath(String name) {
        return INDEX_ROOT.resolve(name);
    }

    private static Path requireExistingIndex(String name) {
        Path indexPath = indexPath(name);
        if (!Files.exists(indexPath)) {
            throw new IllegalStateException("No such index: " + name + " (create it first)");
        }
        return indexPath;
    }

    private static float[] randomVector(Random random) {
        float[] vector = new float[DIMENSIONS];
        for (int i = 0; i < DIMENSIONS; i++) {
            vector[i] = random.nextFloat();
        }
        return vector;
    }

    private static void requireArgs(String[] args, int expected, String form) {
        if (args.length < expected) {
            throw new IllegalArgumentException("Usage: " + form);
        }
    }

    private static void usage() {
        System.out.println("""
                Commands:
                  create <name>       create an empty index
                  insert <name> <n>   insert n random vectors
                  search <name> <k>   find top k neighbours of a random vector
                  pid                 print this process's PID
                  help                show this help
                  exit | quit         leave the tool""");
    }
}
