### Project structure
* Lucene-index - a tool that can create vector indexes and do a basic operation over them
* examples - a set of ebpf profiler examples.

### Page faults demo

Lucene memory-maps files, and when there is a search (or population) operation and they are not in RAM, the OS needs to load them from disk. We (the index team) want to monitor when this happens, as it affects search latency.
This demo shows how to monitor such page faults.

### How to run the demo.

The demo works only on Linux, as eBPF profiler tracing is a kernel feature.

The examples/lucene_page_faults.bpf.c contains the script that will be loaded in kernel and populate the page fault counter.
The measurement happens per i-node path prefix. So if you have k indexes in a folder, the eBPF exporter will report k metrics.
There is no way to pass dynamic parameters to the script, as the script is loaded into the kernel, so before running it, change the prefix path (/home/akarasavov/indexes) that is monitored.

Each change to a C file requires rebuilding the bpf.o object. To compile the C files, execute:
```bash
 make -C examples build
```

When the C files are compiled, you can start the eBPF exporter:

```bash
sudo docker run --rm -it --privileged -p 9435:9435   -v examples:/examples   ghcr.io/cloudflare/ebpf_exporter   --config.dir=/examples --config.names=lucene_page_faults
```

In case you want to monitor how lucene indexes behave, then run the lucene-index creator:
```bash
cd lucene-index
mvn clean package
java -jar target/index-manager.jar
```

The Lucene creator creates an indexes folder in the directory where the tool is run. The full path to the index folder needs to match what the C file monitors.
To see page faults, do these actions in the defined order:

1. Create an index in the tool. 
2. Ingest 10000 vectors.
3. Offload the OS page cache.
```bash
echo 1 | sudo tee /proc/sys/vm/drop_caches
```
4. Search 100 vectors in the created index.
5. Read the reported metrics from the eBPF exporter.
```bash
curl -s http://localhost:9435/metrics | grep page_faults_per_index
```