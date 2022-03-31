# Simple local Spring vulnerability scanner

(Written in Go because, you know, "write once, run anywhere.")

This is a simple tool that can be used to find instances of Spring
that are vulnerable to the recent "spring4shell" vulnerability in
installations of Java software such as web applications. JAR and WAR
archives are inspected and class files that are known to be vulnerable
are flagged. The scan happens recursively: WAR files containing WAR
files containing JAR files containing vulnerable class files ought to
be flagged properly.

The scan tool currently checks for known build artifacts that have
been obtained through Maven Central. From-source rebuilds as they are
done for Linux distributions may or may not be recognized.

Binaries for x86_64 Windows, Linux, MacOSX for tagged releases are
provided via the
[Releases](https://github.com/hillu/local-spring-vuln-scanner/releases)
page.

# Using the scanner

```
$ ./local-spring-vuln-scanner [--verbose] [--quiet] \
    [--exclude /path/to/exclude …] \
	[--scan-network] \
	[--log /path/to/file.log] \
    /path/to/app1 /path/to/app2 …
```

The `--verbose` flag will show every .jar and .war file checked, even if no problem is found.

The `--quiet` flag will supress output except for indicators of a known vulnerability.

The `--log` flag allows everythig to be written to a log file instead of stdout/stderr.

Use the `--exclude` flag to exclude subdirectories from being scanned. Can be used multiple times.

The `--scan-network` flag tells the scanner to search network filesystems (disabled by default). This has not been implemented for Windows.

If class files indicating one of the vulnerabilities are found,
messages like the following are printed to standard output:
``` console
local-spring-vuln-scanner - a simple local Spring vulnerability scanner

Checking for vulnerabilities: spring4shell
examining /path/to/spring-boot-0.0.1-SNAPSHOT.jar
indicator for vulnerable component found in /path/to/spring-boot-0.0.1-SNAPSHOT.jar::BOOT-INF/lib/spring-beans-5.3.17.jar (org/springframework/beans/CachedIntrospectionResults.class): CachedIntrospectionResults.class  spring 5.3.0-5.3.17 spring4shell

Scan finished
```

# Building from source

Install a [Go compiler](https://golang.org/dl).

Run the following commands in the checked-out repository:
```
go build
```

# License

GNU General Public License, version 3

# Author

Hilko Bengen <<bengen@hilluzination.de>>

# See also

- [local-log4j-vuln-scanner](https://github.com/hillu/local-log4j-vuln-scanner)
